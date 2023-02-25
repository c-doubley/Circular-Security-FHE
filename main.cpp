#include <iostream>
#include <math.h>
#include <sys/time.h>
#include <helib/helib.h>


int main(int argc, char **argv)
{
    long p = 1021;
    long r = 1;
    long L = 4;
    long c = 2;
    long k = 128;
    long s = 0;
    long d = 0;
    long w = 64;
    long m = 65536;
    
    timespec t1, t2;
    helib::resetAllTimers();
    helib::setTimersOn();

    //std::cout << "finding m..." << std::flush;
    //long m = helib::FindM(k,L,c,p,d,s,0);
    //std::cout << "m = "<< m << std::endl;

    std::cout << "Initializing context..." << std::flush;
    helib::Context context(m,p,r);  //initialize context
    buildModChain(context, L, c);  //modify the context
    std::cout << "OK!" << std::endl;

    std::cout << "Creating polynomial..." << std::flush;
    std::cout << "OK!" << std::endl;

    std::cout << "Generating keys..." << std::flush;
    helib::SecKey secretKey(context);  //construct a secret key structure

    const helib::PubKey& publicKey = secretKey;  //An "upcast": FHESecKey is a subclass of FHEPubKey

    clock_gettime(CLOCK_MONOTONIC, &t1);
    secretKey.GenSecKey(w);  //actually generate a secret key with Hamming weight w
    clock_gettime(CLOCK_MONOTONIC, &t2);
    std::cout << "GenSecKey :" <<  ((t2.tv_sec - t1.tv_sec) * pow(10,9) + t2.tv_nsec - t1.tv_nsec) << " ns" << std::endl;
	
    //std::cout << "OK!" << std::endl;

    helib::Ctxt ctxt1(publicKey);
    helib::Ctxt ctxt2(publicKey);
    helib::Ctxt ctxt3(publicKey);
    helib::Ctxt ctxt4(publicKey);   
   
    publicKey.Encrypt(ctxt1, NTL::to_ZZX(120));  //encrypt the value 2
    std::cout << "NoiseBound of Encryption 120: " << ctxt1.getNoiseBound() <<std::endl;

    publicKey.Encrypt(ctxt2, NTL::to_ZZX(246));  //encrypt the value 3
    std::cout << "NoiseBound of Encryption 246: " << ctxt2.getNoiseBound() <<std::endl;

    //std::cout << "ciphertext size1 of Encryption: " << ctxt1.size();
    publicKey.Encrypt(ctxt3, NTL::to_ZZX(4));  //encrypt the value 1
    std::cout << "NoiseBound of Encryption 4: " << ctxt3.getNoiseBound() <<std::endl;

    clock_gettime(CLOCK_MONOTONIC, &t1);
    publicKey.Encrypt(ctxt4, NTL::to_ZZX(150));  //encrypt the value 2
    std::cout << "NoiseBound of Encryption 150: " << ctxt4.getNoiseBound() <<std::endl;

    clock_gettime(CLOCK_MONOTONIC, &t2);
    std::cout << "Encrypt :" <<  ((t2.tv_sec - t1.tv_sec) * pow(10,9) + t2.tv_nsec - t1.tv_nsec) << " ns" << std::endl;



    helib::Ctxt ctSum = ctxt1;  //create a ciphertext to hold the sum and initialize it with Enc(2)
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ctSum += ctxt2;
    std::cout << "NoiseBound of Sum: " << ctSum.getNoiseBound() <<std::endl;

    clock_gettime(CLOCK_MONOTONIC, &t2);
    std::cout << "Add :" <<  ((t2.tv_sec - t1.tv_sec) * pow(10,9) + t2.tv_nsec - t1.tv_nsec) << " ns" << std::endl;
	


    helib::Ctxt ctProduct = ctxt3;  //create a ciphertext to hold the sum and initialize it with Enc(2)
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ctProduct.multiplyBy(ctxt4);
    std::cout << "NoiseBound of Mult: " << ctProduct.getNoiseBound() <<std::endl;

    //std::cout << "ciphertext size1 of Mult: " << ctProduct.size();
    clock_gettime(CLOCK_MONOTONIC, &t2);
    std::cout << "Product :" <<  ((t2.tv_sec - t1.tv_sec) * pow(10,9) + t2.tv_nsec - t1.tv_nsec) << " ns" << std::endl;

    NTL::ZZX ptProduct;  //create a ciphertext to hold the plaintext of the sum
    clock_gettime(CLOCK_MONOTONIC, &t1);
    secretKey.Decrypt(ptProduct, ctProduct);
    clock_gettime(CLOCK_MONOTONIC, &t2);
    std::cout << "Decrypt :" <<  ((t2.tv_sec - t1.tv_sec) * pow(10,9) + t2.tv_nsec - t1.tv_nsec) << " ns" << std::endl;
    std::cout << "150 * 4 = " << ptProduct[0] << std::endl;
	
    NTL::ZZX ptSum;  //create a ciphertext to hold the plaintext of the sum
    secretKey.Decrypt(ptSum, ctSum);
    std::cout << "120 + 246 = " << ptSum[0] << std::endl;

    helib::setTimersOff();
    std::ofstream file;	
    file.open("file.txt");	
    helib::printNamedTimer(file, "GenSecKey");
    //helib::printNamedTimer(file, "GenKeySWmatrix");
    helib::printNamedTimer(file, "skEncrypt");
    helib::printNamedTimer(file, "Decrypt");
    //helib::printNamedTimer(file, "addPart");
    helib::printNamedTimer(file, "multiplyBy");
    //helib::printNamedTimer(file, "multLowLvl");
    helib::printNamedTimer(file, "reLinearize");

    return 0;
}
