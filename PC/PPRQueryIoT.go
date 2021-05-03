/*
	PPRQueryIoT.go - 2-bit version (default)
	By Hongcheng Xie at Department of Computer Science, City University of Hong Kong, Hong Kong SAR, China

	The program be transformed to other versions by changing the const variables.
*/
package main

import (
	"bytes"
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strconv"
)

// the structure of the ciphertext of one block in query
type QueryBlockCipher struct {
	subIndex uint8  // the subIndex to optimize the searching performance
	cipher   []byte // the actual ciphertext
}

// the structure of one value in the range [a,b]
type QueryRangeCipher struct {
	blockCipher [32 / blockSize]QueryBlockCipher // the set of each block's cipher
}

// the structure of the whole query
type QueryCipher struct {
	lower QueryRangeCipher // the lower bound
	upper QueryRangeCipher // the upper bound
}

// the structure of one block in index
type IndexBlockCipher struct {
	// the sub-index list of one block [the number of sub-index types (each one is denoted as A)][the max conflicts in one sub-index]. the content is the array index whose sub-index is A. the unused item will be -1
	subIndex [subIndexSize][subIndexSize]uint8
	// the ciphertexts of one block
	ciphers [subIndexSize][]byte
}

// the structure of one item in index
type IndexCipher struct {
	// pubCipher   *bn256.G1                        // the public cipher shared by the below ciphers
	gamma       []byte
	blockCipher [32 / blockSize]IndexBlockCipher // the set of each block's cipher

	note int // the note of one index item
}

const (
	blockSize    int   = 2  //the number of bits in one block
	subIndexSize int64 = 3  // the size of subIndex (i.e. 2^{blockSize}-1). subIndexSize is the same as the number of ciphers in one block in index
	indexSize    int   = 50 // the size of the index
)

var (
	filename       string        = "1d.data"                      // the filename of processed test data
	testData       [800]int                                       // the 1-D test data list
	index          []IndexCipher = make([]IndexCipher, indexSize) // the index of IoT devices
	queryCipher    QueryCipher                                    // the query
	blockPossValue int64                                          // the possible maximum value in one block (i.e. 2^{blockSize})
	k              []byte        = make([]byte, 256)              // HMAC key (length: 256 bits)
	res                          = list.New()                     // the search result
)

// initialize(): initialize the basic parameters
func initialize() {
	// generate the HMAC key
	_, err := rand.Read(k)
	if err != nil {
		fmt.Println(err)
	}

	// calculate blockPossValue
	blockPossValue = subIndexSize + 1
}

// readData(): read the test data from the file
func readData() {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	for i := 0; i < 800; i++ { // the size of test data is 800
		n, err := fmt.Fscanln(f, &testData[i])
		if n == 0 || err != nil {
			fmt.Println(err)
			break
		}
	}
}

// getHashedValue: compute the hash value in the power part of index and query (i.e. G_K(H(prefix),iStr)) (blockId: the current block number)
func getHashedValue(iStr string, prefix int64, blockId int) *big.Int {
	// the first block, no prefix
	if blockId == 0 {
		iStrBytes := []byte(iStr)           // convert string to byte
		hmac_ins := hmac.New(sha256.New, k) // create an HMAC instance by key k
		hmac_ins.Write(iStrBytes[:])        // generate the HMAC data for iStr
		hashed := hmac_ins.Sum(nil)
		hashedValue := new(big.Int).SetBytes(hashed[:]) // convert bytes to big.Int
		return hashedValue
	} else { // include the prefix
		// hash the prefix by SHA256
		prefixBytes := []byte(strconv.FormatInt(prefix, 10))
		hashedPrefix := sha256.Sum256(prefixBytes[:])
		iStrByte := []byte(iStr) // convert string to byte

		// combine hashedPrefix and iStrByte to finalBytes
		var buffer bytes.Buffer
		buffer.Write(hashedPrefix[:])
		buffer.Write(iStrByte[:])
		finalBytes := buffer.Bytes()

		// generate HMAC data for finalBytes
		hmac_ins := hmac.New(sha256.New, k) // create an HMAC instance by key k
		hmac_ins.Write(finalBytes[:])       // generate HMAC data for finalBytes
		hashed := hmac_ins.Sum(nil)
		hashedValue := new(big.Int).SetBytes(hashed[:]) // convert bytes to big.Int
		return hashedValue
	}
}

// F(*big.Int,[]byte): another hash function
func F(v *big.Int, gamma []byte) []byte {
	vBytes := v.Bytes()
	hmac_ins := hmac.New(sha256.New, gamma)
	hmac_ins.Write(vBytes[:])
	hashed := hmac_ins.Sum(nil)
	return hashed
}

// indexBlockEnc(int64,int64,int,[]byte): encrypt one block in index
func indexBlockEnc(block int64, prefix int64, blockId int, gamma []byte) IndexBlockCipher {
	var (
		ret         IndexBlockCipher
		i           int64
		subIndexPos []int = make([]int, subIndexSize) // the next available space of each sub-index's list
		cipherPos   int   = 0                         // the next available space of ciphertext list
	)

	for i = 0; i < subIndexSize; i++ {
		subIndexPos[i] = 0
	}

	for i = 0; i < subIndexSize; i++ { // initialize the tag list with 100 (one value out of range, i.e. no block's id is 100)
		for j := 0; j < int(subIndexSize); j++ {
			ret.subIndex[i][j] = 100
		}
	}

	for i = 0; i < blockPossValue; i++ {
		if i == block { // do not encrypt the equal block
			continue
		} else if i < block { // the current variable is smaller than the current block
			iStr := strconv.FormatInt(i, 10) + ">"
			exp := getHashedValue(iStr, prefix, blockId) // get the hash value in power part of ciphertext

			// calculate the sub-index value (G_k mod subIndexSize)
			subIndex, _ := strconv.Atoi(new(big.Int).Mod(exp, big.NewInt(subIndexSize)).String())
			ret.subIndex[subIndex][subIndexPos[subIndex]] = uint8(cipherPos)
			subIndexPos[subIndex]++

			// generate the ciphertext
			ret.ciphers[cipherPos] = F(exp, gamma)
			cipherPos++
		} else { // the current variable is larger than the current block (the process procedure is similar)
			iStr := strconv.FormatInt(i, 10) + "<"
			exp := getHashedValue(iStr, prefix, blockId) // get the hash value in power part of ciphertext

			// calculate the sub-index value (G_k mod subIndexSize)
			subIndex, _ := strconv.Atoi(new(big.Int).Mod(exp, big.NewInt(subIndexSize)).String())
			ret.subIndex[subIndex][subIndexPos[subIndex]] = uint8(cipherPos)
			subIndexPos[subIndex]++

			// generate the ciphertext
			ret.ciphers[cipherPos] = F(exp, gamma)
			cipherPos++
		}
	}
	return ret
}

// indexItemEnc(int, int): encrypt one item in index (v: the value to be encrypted, id: the next available index place)
func indexItemEnc(v int, id int) {
	var prefix int64

	vStr := strconv.FormatInt(int64(v), 2) // calculate the binary value
	vStr = fmt.Sprintf("%032s", vStr)      // pad to 32 bits

	index[id].gamma = make([]byte, 256) // the nonce
	rand.Read(index[id].gamma)
	index[id].note = v

	for i := 0; i < 32/blockSize; i++ {
		block, _ := strconv.ParseInt(vStr[i*blockSize:i*blockSize+blockSize], 2, 0) // the block contains blockSize bits
		if i == 0 {                                                                 // the first block (no prefix)
			prefix = -1
		} else { // other (has prefix)
			prefix, _ = strconv.ParseInt(vStr[0:i*blockSize], 2, 0)
		}
		index[id].blockCipher[i] = indexBlockEnc(block, prefix, i, index[id].gamma[:]) // encrypt the block
	}
}

// indexEnc: encrypt all the index items
func indexEnc() {
	for i := 0; i < indexSize; i++ {
		indexItemEnc(testData[i], i)
	}
}

// queryBlockEnc(string, int64, int): generate the ciphertext for one block (blockStr: the string which is the combination of block value and the operator)
func queryBlockEnc(blockStr string, prefix int64, blockId int) QueryBlockCipher {
	var ret QueryBlockCipher
	exp := getHashedValue(blockStr, prefix, blockId)                                      // get the hash value in power part of ciphertext
	subIndex, _ := strconv.Atoi(new(big.Int).Mod(exp, big.NewInt(subIndexSize)).String()) // calculate the sub-index value (G_k mod subIndexSize)
	ret.subIndex = uint8(subIndex)

	// generate the ciphertext
	ret.cipher = exp.Bytes()
	return ret
}

// queryRangeEnc(uint32, bool): generate the ciphertext for one bound. parameter bound is the value of one bound. parameter isLower defines whether bound is the lower bound or not(i.e. the upper bound)
func queryRangeEnc(bound uint32, isLower bool) {
	var (
		res      QueryRangeCipher
		operator string
		prefix   int64
	)

	// get the operator
	if isLower == true { // if bound is the lower bound
		operator = ">"
	} else { // if bound is the upper bound
		operator = "<"
	}

	boundStr := strconv.FormatInt(int64(bound), 2) // calculate the binary value
	boundStr = fmt.Sprintf("%032s", boundStr)      //pad into 32 bits

	for i := 0; i < 32/blockSize; i++ {
		block, _ := strconv.ParseInt(boundStr[i*blockSize:i*blockSize+blockSize], 2, 0) // the block contains blockSize bits
		if i == 0 {                                                                     // the first block (no prefix)
			prefix = -1
		} else { // other (has prefix)
			prefix, _ = strconv.ParseInt(boundStr[0:i*blockSize], 2, 0)
		}
		blockStr := strconv.FormatInt(block, 10) + operator
		res.blockCipher[i] = queryBlockEnc(blockStr, prefix, i)
	}

	if isLower == true { // if bound is the lower bound
		queryCipher.lower = res
	} else { // if bound is the upper bound
		queryCipher.upper = res
	}
}

// queryEnc(uint32,uint32): generate the ciphertext of query [lowerBound,upperBound]
func queryEnc(lowerBound uint32, upperBound uint32) {
	queryRangeEnc(lowerBound, true)
	queryRangeEnc(upperBound, false)
}

// search(): perform the search procedure
func search() {
	var lowerMatchedList = list.New() // the list which stores the lower-matched index
	for i := 0; i < indexSize; i++ {  // scan each index item (lower)
		var isMatched bool = false
		for j := 0; j < 32/blockSize; j++ { // scan each block
			for k := 0; k < int(subIndexSize); k++ { // scan all the blocks which their tags are the same as the query's
				if index[i].blockCipher[j].subIndex[queryCipher.lower.blockCipher[j].subIndex][k] == 100 { // if all the items with the same sub-index in one block have been checked
					break
				}
				targetItem := index[i].blockCipher[j].subIndex[queryCipher.lower.blockCipher[j].subIndex][k] // get the item's index

				// perform the hash operation to check if this item is matched by the query lower-bound block
				k1Byte := F(new(big.Int).SetBytes(queryCipher.lower.blockCipher[j].cipher), index[i].gamma)
				k2Byte := index[i].blockCipher[j].ciphers[targetItem]

				if bytes.Equal(k1Byte, k2Byte) {
					isMatched = true
					break
				}
			}
			if isMatched == true { // if one item in a block matches, the whole index item matches
				break
			}
		}
		if isMatched == true { // lowerMatchedList will store all the indexes' positions which match the lower-bound
			lowerMatchedList.PushBack(i)
		}
	}

	for e := lowerMatchedList.Front(); e != nil; e = e.Next() { // find which one matches the upper bound from the list whose item matches the lower bound
		var (
			i              = e.Value.(int)
			isMatched bool = false
		)
		for j := 0; j < 32/blockSize; j++ { // scan each block
			for k := 0; k < int(subIndexSize); k++ { // scan all the blocks which their tags are the same as the query's
				if index[i].blockCipher[j].subIndex[queryCipher.upper.blockCipher[j].subIndex][k] == 100 { // if all the items with the same sub-index in one block have been checked
					break
				}
				targetItem := index[i].blockCipher[j].subIndex[queryCipher.upper.blockCipher[j].subIndex][k] // get the item's index

				// perform the hash operation to check if this item is matched by the query lower-bound block
				k1Byte := F(new(big.Int).SetBytes(queryCipher.upper.blockCipher[j].cipher), index[i].gamma)
				k2Byte := index[i].blockCipher[j].ciphers[targetItem]

				if bytes.Equal(k1Byte, k2Byte) {
					isMatched = true
					break
				}
			}
			if isMatched == true { // if one item in a block matches, the whole index item matches
				break
			}
		}
		if isMatched == true { // insert the matched index into the result list
			res.PushBack(index[i].note)
		}
	}
}

// main(): the main function
func main() {
	initialize()
	fmt.Println("init completed.")
	readData()
	fmt.Println("readData completed.")
	indexEnc()
	fmt.Println("indexEnc completed.")
	queryEnc(10000, 20000)
	fmt.Println("queryEnc completed.")
	search()
	fmt.Println("search completed.")
	for e := res.Front(); e != nil; e = e.Next() {
		fmt.Println(e.Value)
	}
}
