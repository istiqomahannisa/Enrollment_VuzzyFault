%Author: Annisa Istiqomah Arrahmah
%Date: 21 July 2016
%Description: produce genuine points in early stage from dummy feature
%points and dummy secret keys

%M = minutiae points in the form of tuple matrix m = (mx my)
%{
M = [175    28;
   176    28;
   117    35;
   199    35;
   107    38;
   109    38;
   155    52;
   152    53;
   215    56;
   154    63;
    92    65;
   154    65;
   158    65;
    83    68;
    88    75;
   116    75;
    63    76;
    83    76;
    84    76;
   114    76;
    81    77;
   104    77;
   110    77;
    61    78;
    40    82;
    88    84;
   243    85;
    36    86;
   245    86;
    81    87;
    87    92;
    91    92;
   189    92;
   255    93;
    29    94;
    36    94;
   179    94;
   193    94;
   194    95;
    32    99;
   188   100;
   213   100;
   215   101;
    62   105;
    57   108;
    73   108;
    84   109;
    66   110;
    25   113;
    63   113;
   229   118;
   164   122;
   155   134;
   124   135];
   %}
M= [20 10;31 42;51 64;44 56;26 34;2 4;3 4;4 5;1 1;12 3;56 7;34 5;34 56;90 45];
% degree of polynomial 8th
p = 8;
%S = cryptographic key is 144 bit (ex. AES 128 bits plus CRC 16 bits) 
%{
S_ori = [1 1 0 1 1 0 1 0 1 0 1 0 1 0 1 0; 
         1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0;
         1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0; 
         1 0 1 0 1 0 1 0 1 0 1 1 1 1 1 0;
         0 0 1 0 1 1 1 0 1 1 0 1 1 1 0 1;
         1 1 0 1 1 0 1 0 1 0 1 0 1 0 1 0;
         1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0;
         1 0 1 0 1 0 1 0 1 0 1 0 1 0 1 0;
         1 0 1 0 1 0 1 0 1 0 1 1 1 1 1 0];
%}
S_ori=[ 0 1 0 0;
    0 0 1 0;
    1 0 1 0;
    0 1 1 0;
    1 1 1 0;
    1 1 1 0;
    1 0 0 1;
    0 0 0 1;
    0 0 1 0];
%convert binary to decimal of the secret key
S=bi2de(S_ori);

%concate each minutiae coordinate to form x-axis value for fuzzy vault
%template
[m,n]=size(M);
Vx=zeros(m,1);
for i=1:m
Vx(i,1)=str2num(strcat(num2str(M(i,1)),num2str(M(i,2))));
end

Vx= [1;30;70;100;150;200;250;300;350;400;450;500;1000;2323];

%polynomial reconstruction of S to form y-axis value for fuzzy vault
[k,l]=size(S);
Vy=zeros(m,1);
for i=1:m
    for j=1:k
    Vy(i)=Vy(i)+S(j)*Vx(i)^(k-j);
    end
end

%polynomial reconstruction v.2
%Vy(:1)

%concatenate Vx and Vy to make G as a tuple of (Vx,Vy)
G=cat(2,Vx,Vy);

%Chaff Generator
%Input: V as a tuple of (Vx,Vy) and it is sorted ascending
%       S as a secret key K
%Output: Chaff points N that are inserted to the Vault V'.
%Number of C as Chaff points. It depends on the number of Genuine Vault.

%Initialization
%The minimum ratio is 10:1
C=zeros(10*m,2);
%The Genuine point is sorted ascending and concatenated together with S
ho=cat(1,sort(G(:,1)),S);

%SHA function of ho, follows the formula : ho <- SHA(ho)
%The choosen SHA function : SHA-256
%Output format : double
%Input type: array
Opt=struct('Format','double','Method','SHA-512','Input','array');
ho_1=DataHash(ho,Opt);
ho_dummy=DataHash(ho_1,Opt);

%Initialization
i=1;
C_numb=0;
G_numb=m;
MaxLoop=500;

%main chaff point generator
while (C_numb < 10*G_numb) && i < MaxLoop
    a=ho_dummy(1);
    b=ho_dummy(end);
    tempChaff=zeros(2,1);
    x=mod(i,G_numb);
    if x==0
        x=G_numb;
    end
    %Linear Projection function
    tempChaff=((1/(1+a^2))*[1 a;a a^2])*([G(x,1); G(x,2)]-[0; b]) + [0; b];
    %Euclidian distance calculation, the minimum distance is 10.7 or 25
    %based on paper by Mohammed Khalil Ghani and 10 based on M.T. Nguyen
    %paper
    d=sqrt((tempChaff(1,1)-G(x,1))^2 + (tempChaff(2,1)-G(x,2))^2);
    %Verification function
    if ismember(tempChaff(1,1),Vx)==0 && ismember(tempChaff(2,1),Vy)==0 && d>10
        C_numb=C_numb+1;
        C(C_numb,:)=rot90(tempChaff);
    end
    i=i+1;
    ho_dummy=DataHash(cat(1,rot90(ho_dummy),S),Opt);
end
V=cat(1,G,C);
V_final=sort(V);
    
        
        
