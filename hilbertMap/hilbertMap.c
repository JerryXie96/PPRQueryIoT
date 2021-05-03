// hilbertMap: convert the test data in two-dimensional space to the coordinates in one-dimensional space
// the code is based on Wikipedia (https://en.wikipedia.org/wiki/Hilbert_curve)

#include <stdio.h>

// rot(int n, int *x, int *y, int rx, int ry): rotate/flip a quadrant
void rot(int n, int *x, int *y, int rx, int ry){
    if(ry == 0){
        if(rx == 1){
            *x=n-1-*x;
            *y=n-1-*y;
        }

        int t=*x;
        *x=*y;
        *y=t;
    }
}

// xy2d(int n, int x, int y): convert (x,y) to d in n*n area
int xy2d(int n, int x, int y){
    int rx,ry,s,d=0;
    for (s=n/2;s>0;s/=2){
        rx=(x&s)>0;
        ry=(y&s)>0;
        d+=s*s*((3*rx)^ry);
        rot(n,&x,&y,rx,ry);
    }
    return d;
}

// main(): main function
int main(){
    int n=200;                     // the space will be divided into n*n cells
    int i,num;
    int x,y;
    FILE *in,*out;

    in=fopen("2d.data","r");        // 2d.data: the test data in 2-D space
    out=fopen("1d.data","w");       // 1d.data: the processed data
    fscanf(in,"%d",&num);           // num: the number of points
    for(i=0;i<num;i++){
        fscanf(in,"%d %d",&x,&y);
        fprintf(out,"%d\n",xy2d(n,x,y));
    }
    fclose(in);
    fclose(out);
    return 0;
}