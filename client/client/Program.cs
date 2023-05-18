using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math.EC;
using System.Diagnostics;


/// this project belongs to d4rkn19ht/ sm1l3isnotbad
/// 

namespace client_server
{

    internal class Program
    {

        TcpClient server;
        // TcpListener listener;


        IPEndPoint IPserver;
        NetworkStream networkStream;

        ECDomainParameters curve;
        AsymmetricCipherKeyPair ecc_keypair;
        ECPublicKeyParameters ecc_pubkey;
        ECPrivateKeyParameters ecc_privatekey;

        byte[] buffer;
        byte[] finalKey;
        string message;
        int bytesRead;
        int messageSize;
        byte[] key = new byte[16];
        void changeCurvebyName(string name)
        {
            X9ECParameters parameter = SecNamedCurves.GetByName(name);
            curve = new ECDomainParameters(parameter);
        }

        void generatingKeypair()
        {
            SecureRandom random = new SecureRandom();

            ECKeyGenerationParameters param_for_key = new ECKeyGenerationParameters(curve, random);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(param_for_key);
            ecc_keypair = generator.GenerateKeyPair();
            ecc_pubkey = (ECPublicKeyParameters)ecc_keypair.Public;
            ecc_privatekey = (ECPrivateKeyParameters)ecc_keypair.Private;
            Console.WriteLine("Key generation completed!!!");
            Console.WriteLine("Public Key");
            Console.WriteLine("X : " + ecc_pubkey.Q.XCoord.ToString());
            Console.WriteLine("Y : " + ecc_pubkey.Q.YCoord.ToString());
            ///Console.WriteLine(ecc_pubkey.Q.GetEncoded().Length);
        }

        void sendPublicKey()
        {
            buffer = ecc_pubkey.Q.GetEncoded();
            networkStream = server.GetStream();
            networkStream.Write(buffer, 0, buffer.Length);
            networkStream.Flush();
        }

        void getOtherPublicKey()
        {
            networkStream = server.GetStream();
            bytesRead = server.ReceiveBufferSize;
            buffer = new byte[bytesRead];
            int len = networkStream.Read(buffer, 0, bytesRead);
            byte[] pub = new byte[len];
            Buffer.BlockCopy(buffer, 0, pub, 0, len);

            ECPoint point = ecc_pubkey.Parameters.Curve.DecodePoint(pub);
            ECPublicKeyParameters otherPublicKey = new ECPublicKeyParameters(point, curve);

            IBasicAgreement ok = AgreementUtilities.GetBasicAgreement("ECDH");
            ok.Init(ecc_privatekey);
            byte[] sharekey = ok.CalculateAgreement(otherPublicKey).ToByteArray();
            finalKey = sharekey;
            Console.WriteLine("Calculating share key completed!!!");
            Console.Write("Share key: " + BitConverter.ToString(sharekey).Replace("-", String.Empty));
            Console.WriteLine("");
            Buffer.BlockCopy(finalKey, 0, key, 0, 16);
        }
        /// <summary>
        /// currently only one curve - secp256k1, will add more curve later
        /// </summary>
        /// 
        static byte[] encrypt_msg(byte[] KEY, byte[] IV, string msg)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7");
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(KEY), IV);
            cipher.Init(true, parameters);

            byte[] plaintext = Encoding.UTF8.GetBytes(msg);
            return cipher.DoFinal(plaintext);
        }

        static string decrypt_msg(byte[] KEY, byte[] IV, byte[] enc)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7");
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(KEY), IV);
            cipher.Init(false, parameters);

            byte[] decryptedBytes = cipher.DoFinal(enc);
            return Encoding.UTF8.GetString(decryptedBytes);

        }

        void Decrypt_and_show(byte[] ok)
        {
            byte[] iv = new byte[16];
            Buffer.BlockCopy(ok, 0, iv, 0, 16);
            byte[] enc = new byte[ok.Length - 16];
            Buffer.BlockCopy(ok, 16, enc, 0, ok.Length - 16);
            string msg = decrypt_msg(key, iv, enc);

            Console.Write("Server: ");
            Console.WriteLine(msg);

        }

        string byte_to_hex(byte[] ok)
        {
            return BitConverter.ToString(ok).Replace("-", string.Empty);
        }

        void Encrypt_and_send(string msg)
        {
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.NextBytes(iv);
            byte[] enc = encrypt_msg(key, iv, msg);

            ///test
            ///
            /*
            Console.WriteLine("IV: " + byte_to_hex(iv));
            Console.WriteLine("Enc: " + byte_to_hex(enc));
            */

            byte[] ok = new byte[16 + enc.Length];
            Buffer.BlockCopy(iv, 0, ok, 0, 16);
            Buffer.BlockCopy(enc, 0, ok, 16, enc.Length);
            SendStream(ok);
        }

        void client_side()
        {

            Console.WriteLine("##########################################");
            Console.WriteLine("#                                        #");
            Console.WriteLine("#                 CLIENT                 #");
            Console.WriteLine("#                                        #");
            Console.WriteLine("##########################################");

            changeCurvebyName("secp256k1");
            ConnectToServer();
            generatingKeypair();
            sendPublicKey();
            getOtherPublicKey();
            string msg = "";

            Console.WriteLine("--------  Begin your message here!  --------");
            while (true)
            {
                Console.Write("Your message: ");
                msg = Console.ReadLine().TrimEnd();
                Encrypt_and_send(msg);

                byte[] ok = ReadStream();
                Decrypt_and_show(ok);

            }
        }

            // this feature will be available in server
        /* void server_side()
         {
             changeCurvebyName("secp256k1"); 
             ListenToClient();

             generatingKeypair();
             getOtherPublicKey();
             sendPublicKey();
         }*/

        static void Main(string[] args)
        {
            Program program = new Program();
            program.client_side();
            Console.ReadKey();
        }

        // this feature will be available in server
        /*
        void ListenToClient()
        {
            listener = new TcpListener(IPAddress.Any, 8000);
            listener.Start();
        }
        */

        void ConnectToServer()
        {
            /// this will add when testing on ngrok
            /// 
            /*
            Console.WriteLine("Attemp to connecting to server!");
            
            string servername = "";
            Console.Write("Enter URL of host: ");
            servername = Console.ReadLine();
            var address = Dns.GetHostAddresses(servername);
            Debug.Assert(address.Length > 0);
            var enpoint = new IPEndPoint(address[0], 10312);

            server = new TcpClient();

            server.Connect(enpoint);
            
            */

            server = new TcpClient("localhost", 8080);
        }

        void SendStream(byte[] msg)
        {

            networkStream = server.GetStream();
            networkStream.Write(msg, 0, msg.Length);
            networkStream.Flush();
        }



        byte[] ReadStream()
        {
            byte[] buf = new byte[1024];
            networkStream = server.GetStream();
            int len = networkStream.Read(buf, 0, 1024);
            byte[] ok = new byte[len];
            Buffer.BlockCopy(buf, 0, ok, 0, len);
            return ok;
        }
        /*
        byte[] ReceiveAll()
        {
            networkStream = server.GetStream();
            messageSize = server.ReceiveBufferSize;
            buffer = new byte[messageSize];
            bytesRead = networkStream.Read(buffer, 0, messageSize);
            //message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            return buffer;
        }
        byte[] ReceiveLine() //Hope that the maximum length Receiline will get is lower than 1024
        {
            byte[] recv = new byte[1024];
            networkStream = server.GetStream();
            buffer = new byte[1];
            while(true)
            {
                bytesRead = networkStream.Read(buffer, 0, 1);
                Buffer.BlockCopy(buffer, 0, recv, recv.Length, bytesRead);
                if (Encoding.ASCII.GetString(buffer) == "\n")
                    break;
            }
            return recv;
        }
        */
    }
}
