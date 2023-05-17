using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;

namespace client_server
{
    
    internal class Program
    {

        TcpClient client;
        TcpListener listener;


        IPEndPoint IPserver;
        NetworkStream networkStream;
        byte[] buffer;
        string message;
        int bytesRead;
        int totalBytesRead;
        int messageSize;

        static void Main(string[] args)
        {
            Program program = new Program();
            program.ConnectToServer();
            program.SendMessage();
            program.ReceiveMessage();
            program.ListenToClient();
        }

        void Choose()
        {
            Console.WriteLine("Choose what you want to do: ");
            Console.WriteLine("1. Send message to server");
            Console.WriteLine("2. Receive message from server");
            Console.WriteLine("3. Listen to client");
            Console.WriteLine("4. Exit");
            int choice = Convert.ToInt32(Console.ReadLine());
            switch (choice)
            {
                case 1:
                    SendMessage();
                    break;
                case 2:
                    ReceiveMessage();
                    break;
                case 3:
                    ListenToClient();
                    break;
                case 4:
                    Environment.Exit(0);
                    break;
                default:
                    Console.WriteLine("Wrong choice");
                    break;
            }
        }


        void ListenToClient()
        {
            listener = new TcpListener(IPAddress.Any,8000);
            listener.Start();
        }

        void ConnectToServer()
        {
            Console.WriteLine("Tcp ");
            client = new TcpClient();
            IPserver = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8080);
            client.Connect(IPserver);
        }

        void SendMessage()
        {
            message = "Hello Server";
            buffer = Encoding.ASCII.GetBytes(message);
            networkStream = client.GetStream();
            networkStream.Write(buffer, 0, buffer.Length);
            networkStream.Flush();
            Console.WriteLine("Message sent to server: " + message);
        }

        void ReceiveMessage()
        {
            networkStream = client.GetStream();
            messageSize = client.ReceiveBufferSize;
            buffer = new byte[messageSize];
            bytesRead = networkStream.Read(buffer, 0, messageSize);
            message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            Console.WriteLine("Message received from server: " + message);
        }

    }
}
