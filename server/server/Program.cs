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
using Org.BouncyCastle.Crypto.Paddings;

namespace client_server
{

    internal class Program
    {

        TcpClient client;
         TcpListener listener;


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
        byte[] key;

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
        }

        void sendPublicKey()
        {
            buffer = ecc_pubkey.Q.GetEncoded();
            networkStream = client.GetStream();
            networkStream.Write(buffer, 0, buffer.Length);
            networkStream.Flush();
        }

        void getOtherPublicKey()
        {
            networkStream = client.GetStream();
            bytesRead = client.ReceiveBufferSize;
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
        /// this feature will be available in client
        /*
        void client_side()
        {
            changeCurvebyName("secp256k1");
            ConnectToServer();
            generatingKeypair();
            sendPublicKey();
            getOtherPublicKey();
        }
        */

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

        }
        void Encrypt_and_send(string msg)
        {
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.NextBytes(iv);
            byte[] enc = encrypt_msg(key, iv, msg);
            byte[] ok = new byte[16 + enc.Length];
            Buffer.BlockCopy(iv, 0, ok, 0, 16);
            Buffer.BlockCopy(enc, 0, ok, 16, enc.Length);

        }

        void server_side()
        {
            changeCurvebyName("secp256k1");
            ListenToClient();
            generatingKeypair();
             
            getOtherPublicKey();
            sendPublicKey();
        }

        static void Main(string[] args)
        {
            Program program = new Program();
            //program.client_side();
            program.server_side();
            Console.ReadKey();
        }

        
        void ListenToClient()
        {
            IPAddress address = IPAddress.Parse("127.0.0.1");
            listener = new TcpListener(address, 8080);
            Console.WriteLine("Waiting for connection...");
            listener.Start();
            client = listener.AcceptTcpClient();
            Console.WriteLine("Connecting to client success!");

        }
        
        //this feature will be available in client 
        /*
        void ConnectToServer()
        {
            string servername = "";
            Console.Write("Enter URL of host: ");
            servername = Console.ReadLine();
            var address = Dns.GetHostAddresses(servername);
            Debug.Assert(address.Length > 0);
            var enpoint = new IPEndPoint(address[0], 8080);

            client = new TcpClient();

            client.Connect(enpoint);
        }
        */

        void SendStream(byte[] msg)
        {

            networkStream = client.GetStream();
            networkStream.Write(msg, 0, msg.Length);
            networkStream.Flush();
        }

        byte[] ReadStream()
        {
            byte[] buf = new byte[1024];
            networkStream = client.GetStream();
            int len = networkStream.Read(buf, 0, 1024);
            byte[] ok = new byte[len];
            Buffer.BlockCopy(buf, 0, ok, 0, len);
            return buf;
        }
        byte[] ReceiveAll()
        {
            networkStream = client.GetStream();
            messageSize = client.ReceiveBufferSize;
            buffer = new byte[messageSize];
            bytesRead = networkStream.Read(buffer, 0, messageSize);
            //message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            return buffer;
        }
        byte[] ReceiveLine() //Hope that the maximum length Receiline will get is lower than 1024
        {
            byte[] recv = new byte[1024];
            networkStream = client.GetStream();
            buffer = new byte[1];
            while (true)
            {
                bytesRead = networkStream.Read(buffer, 0, 1);
                Buffer.BlockCopy(buffer, 0, recv, recv.Length, bytesRead);
                if (Encoding.ASCII.GetString(buffer) == "\n")
                    break;
            }
            return recv;
        }
    }
}
