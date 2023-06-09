﻿using System;
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
            ECPoint point = ecc_pubkey.Parameters.Curve.DecodePoint(buffer);
            ECPublicKeyParameters otherPublicKey = new ECPublicKeyParameters(point, curve);

            IBasicAgreement ok = AgreementUtilities.GetBasicAgreement("ECDH");
            ok.Init(ecc_privatekey);
            byte[] sharekey = ok.CalculateAgreement(otherPublicKey).ToByteArray();
            finalKey = sharekey;
            Console.WriteLine("Calculating share key completed!!!");
            Console.Write("Share key: " + BitConverter.ToString(sharekey).Replace("-", String.Empty));
            Console.WriteLine("");
        }
        /// <summary>
        /// currently only one curve - secp256k1, will add more curve later
        /// </summary>
        void client_side()
        {
            changeCurvebyName("secp256k1");
            ConnectToServer();
            generatingKeypair();
            sendPublicKey();
            getOtherPublicKey();
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
            program.client_side();
            // program.changeCurvebyName("secp256k1");
            // program.generatingKeypair();
            Console.ReadKey();
        }


        void ListenToClient()
        {
            listener = new TcpListener(IPAddress.Any,8000);
            listener.Start();
        }

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

        void SendMessage(string message)
        {

            buffer = Encoding.ASCII.GetBytes(message);
            networkStream = client.GetStream();
            networkStream.Write(buffer, 0, buffer.Length);
            networkStream.Flush();
        }

        string ReceiveAll()
        {
            networkStream = client.GetStream();
            messageSize = client.ReceiveBufferSize;
            buffer = new byte[messageSize];
            bytesRead = networkStream.Read(buffer, 0, messageSize);
            message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            return message;
        }

    }
}
