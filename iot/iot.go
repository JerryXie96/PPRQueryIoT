/*
	PPRQueryIoT.go - 2-bit version (default)
	By Hongcheng Xie at Department of Computer Science, City University of Hong Kong, Hong Kong SAR, China

	The program be transformed to other versions by changing the const variables.
*/
package iot

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
	"time"
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
	gamma       []byte                           // the nonce
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
	index          []IndexCipher = make([]IndexCipher, indexSize) // the index of IoT devices
	queryCipher    QueryCipher                                    // the query
	blockPossValue int64                                          // the possible maximum value in one block (i.e. 2^{blockSize})
	k              []byte        = make([]byte, 256)              // HMAC key (length: 256 bits)
	res                          = list.New()                     // the search result
)

var (
	testData = [800]int{16548, 26496, 26630, 36014, 16629, 26630, 26439, 16440, 16486, 25389, 25897, 26630, 26620, 36810, 39176, 36630, 36630, 27111, 36774, 26629, 16440, 28503, 29130, 9130, 36620, 16496, 26377, 26664, 13951, 26004, 29139, 26594, 16630, 16307, 26667, 26640, 26630, 36675, 19129, 26439, 36620, 28987, 26640, 26764, 27039, 39176, 26631, 26772, 6484, 26639, 26584, 36628, 27075, 26342, 11040, 29176, 14084, 29166, 29129, 26675, 26484, 23263, 24165, 24274, 26003, 27039, 26583, 23495, 27397, 27300, 26620, 26628, 19621, 34131, 26630, 16460, 26630, 26631, 23495, 36620, 26451, 26250, 26531, 16486, 36628, 26774, 26568, 26631, 26764, 26628, 15897, 24130, 13877, 29765, 26630, 26630, 26810, 27255, 36631, 27085, 34130, 16754, 39800, 29140, 26628, 18504, 29130, 27255, 26774, 36820, 26640, 26630, 26630, 13950, 20995, 26629, 13315, 26772, 26595, 37029, 26450, 26630, 16341, 26774, 29130, 23639, 26521, 11404, 29129, 36631, 27029, 16342, 26620, 26040, 26450, 26620, 25860, 24140, 26628, 26040, 24274, 27256, 26486, 27255, 33639, 26595, 16763, 29129, 26895, 26532, 26630, 36630, 23494, 23315, 26583, 16484, 18360, 26764, 26763, 26639, 4756, 36810, 26640, 26485, 26810, 26629, 26630, 19128, 24165, 26783, 28397, 15860, 26450, 25859, 16628, 26250, 14084, 26604, 26486, 25815, 26440, 16485, 13314, 26630, 26610, 26387, 26388, 26485, 26414, 27111, 29254, 26280, 26620, 36630, 27436, 16342, 26629, 16486, 27075, 39129, 26639, 27157, 27029, 26568, 36628, 26667, 4048, 27039, 29130, 26773, 26620, 16485, 27255, 23069, 28987, 34130, 26629, 26630, 14083, 26630, 26630, 26640, 19129, 16629, 26628, 27029, 34164, 26773, 26631, 28796, 39176, 26630, 26630, 26630, 25860, 27400, 26666, 24140, 8504, 26629, 26819, 15896, 26640, 26629, 26487, 26486, 24756, 25814, 29032, 26754, 26003, 25128, 26610, 26630, 27029, 26629, 13950, 36631, 26640, 26629, 24263, 26772, 26619, 26629, 32889, 36628, 25860, 26486, 27029, 36810, 26439, 34140, 26783, 26640, 16487, 37255, 37400, 26629, 28504, 23541, 36629, 17255, 26604, 28986, 36810, 26629, 26604, 29308, 27112, 36775, 36040, 24104, 32680, 21610, 22680, 29131, 16484, 5715, 26639, 26620, 36763, 26630, 26620, 27111, 27400, 26783, 26630, 16430, 28360, 26640, 26620, 26487, 13315, 26487, 26631, 26450, 25860, 26666, 23495, 13951, 26630, 16430, 26584, 16295, 26665, 26004, 29128, 36629, 26905, 23495, 36630, 26450, 29755, 26619, 25994, 26630, 27112, 16595, 26665, 25860, 26764, 27255, 15860, 26640, 26675, 26619, 26675, 26629, 29139, 27400, 29176, 29130, 6583, 25860, 25635, 23485, 24756, 3135, 26620, 16584, 23950, 22860, 26666, 26630, 26630, 28841, 16450, 26772, 26184, 26620, 26619, 26394, 28504, 36630, 29585, 26820, 26631, 26639, 26630, 29310, 29254, 23951, 26630, 16450, 36664, 26584, 25234, 26531, 26487, 16630, 27111, 27397, 26665, 20000, 26584, 28986, 28396, 26343, 16774, 36620, 8503, 28996, 26630, 24130, 29130, 26774, 26487, 36775, 16783, 26630, 26764, 36629, 27255, 26620, 26629, 14274, 26630, 39129, 26628, 29621, 26620, 16486, 26629, 9139, 28360, 29130, 27076, 29128, 21966, 24120, 26003, 15870, 26584, 29131, 36630, 26820, 36629, 14084, 26628, 26810, 36631, 26630, 26439, 0, 26640, 26640, 26387, 29309, 16414, 18996, 27012, 26630, 26639, 26004, 28987, 28360, 27256, 24263, 16486, 16629, 26772, 26148, 16628, 33485, 26810, 16594, 26485, 27255, 26250, 23494, 36809, 36640, 26773, 29310, 26630, 36630, 26594, 16450, 25815, 26630, 26620, 36630, 27076, 26003, 36628, 15090, 25860, 28396, 27039, 26014, 33494, 16628, 26487, 18986, 26763, 19129, 16594, 26630, 36667, 17869, 29140, 21630, 16486, 33639, 14273, 27255, 29129, 26630, 29621, 26630, 26639, 13951, 26676, 25870, 27002, 27029, 16784, 26640, 26439, 26675, 16532, 24140, 18996, 14038, 26628, 25860, 26604, 25995, 26676, 26630, 24140, 23494, 27255, 29319, 27265, 25859, 25859, 16629, 26584, 36640, 17075, 29129, 36620, 25995, 26629, 26754, 16763, 26630, 37075, 27289, 26460, 29130, 26440, 14094, 26676, 26639, 7256, 26775, 36667, 26307, 21966, 26584, 24130, 26574, 26628, 26628, 26630, 28996, 26450, 29765, 28504, 16629, 34275, 24130, 23315, 26629, 26610, 26450, 26810, 36667, 26584, 36183, 26629, 26041, 23495, 28360, 28986, 39310, 26522, 27112, 26754, 26630, 16629, 36628, 26306, 29320, 26764, 26496, 36630, 28541, 26820, 29310, 36639, 23950, 26630, 16583, 26628, 29130, 9129, 16629, 26496, 26675, 26630, 26631, 36629, 16450, 26630, 23495, 6568, 24502, 27255, 26631, 27397, 26630, 25815, 29139, 36773, 14275, 26763, 25994, 26306, 28360, 39274, 27255, 36773, 26619, 26764, 26630, 26619, 23904, 29284, 26640, 26629, 26194, 39130, 23494, 37256, 39032, 14275, 26763, 26594, 15896, 16584, 27445, 11041, 24274, 26619, 26280, 26388, 29175, 25860, 36620, 16487, 29264, 22255, 24273, 26341, 26631, 26629, 14084, 26630, 37292, 14074, 26905, 26665, 26440, 13299, 26631, 28796, 25815, 26774, 26495, 36610, 29166, 26568, 26584, 29176, 26620, 36630, 26763, 16439, 16675, 36809, 27076, 26763, 26486, 15859, 26594, 26630, 39166, 26630, 26630, 25995, 26810, 26819, 39176, 14094, 23069, 28359, 26594, 25859, 26574, 27111, 14756, 26307, 6394, 26631, 10799, 26754, 23541, 13314, 26450, 26664, 36666, 38683, 26667, 27435, 26630, 27029, 26905, 26808, 26774, 26584, 26594, 24263, 26630, 26620, 26003, 26810, 26620, 26630, 26665, 26628, 26440, 26451, 36630, 26394, 28987, 26548, 16487, 26631, 16531, 26630, 3914, 26630, 26620, 27156, 36664, 26640, 25860, 26630, 39131, 26629, 28796, 26486, 26631, 16487, 29175, 16485, 25860, 23648, 27002, 17256, 26014, 26487, 21450, 27265, 29131, 17256, 9129, 29130, 26485, 27029, 26548, 26675, 26629, 24263, 24275, 26619, 19131, 26630, 26595, 19140, 16628, 27111, 27111, 26496, 26484, 36966, 26620}
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

				// perform the bilinear map to check if this item is matched by the query lower-bound block
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

				// perform the bilinear map to check if this item is matched by the query lower-bound block
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

// Test(): the main function
func Test() string {
	var t int64 = 0 // the computation cost
	initialize()
	indexEnc()
	queryEnc(10000, 20000)

	// test the computation performance
	for i := 0; i < 10; i++ {
		t1 := time.Now()
		search()
		t += time.Since(t1).Microseconds()
	}

	return fmt.Sprintln(float64(t) / 10)
}
