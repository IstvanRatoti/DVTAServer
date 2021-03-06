﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ServerDataHandling;
using System.Threading.Tasks;
using System.Threading;

namespace DVTA_CTF_Server
{
    class Server
    {
        public static DBAccessClass dBAccess;
        public static string adminHash = "FLAG{c134n_up_d4v3}";
        public static string clientHash = "6d8b1411b0d1b56a373e260675a451478867f35e5218e8d28c8156f50919629b";

        private static void ProcessClientRequest(object obj)
        {
            TcpClient client = (TcpClient)obj;

            NetworkStream stream = client.GetStream();
            byte[] request = new byte[65535];
            string requestString;
            string command, arguments;

            // Read data.
            stream.Read(request, 0, request.Length);
            requestString = Encoding.UTF8.GetString(request);

            // Get the first 5 characters, that identify the command sent to the server.
            command = requestString.Substring(0, 5);
            // Only pass the arguments to each handling class.
            arguments = requestString.Substring(6);
            switch (command)
            {
                // Client commands
                case "login":
                    Handler.HandleLogin(client, arguments);
                    break;
                case "regis":
                    Handler.HandleRegister(client, arguments);
                    break;
                case "dlxml":
                    Handler.HandleDownloadUserXML(client, arguments);
                    break;
                case "ulxml":
                    Handler.HandleUploadUserXML(client, arguments);
                    break;
                case "vwprf":
                    Handler.HandleViewProfile(client, arguments);
                    break;
                // Unused command
                case "pthlg":
                    Handler.HandlePassTheHashLogin(client, arguments);
                    break;
                // Admin commands
                case "tstdb":
                    Handler.HandleTestDBConnection(client, arguments);
                    break;
                case "bckup":
                    Handler.HandleBackupFiles(client, arguments);
                    break;
                case "chklg":
                    Handler.HandleCheckLog(client, arguments);
                    break;
                default:
                    Handler.HandleUnknownCommand(client, arguments);
                    break;
            }
        }

        static void Main(string[] args)
        {
            // Establish the connection to the server.
            dBAccess = new DBAccessClass();
            try
            {
                dBAccess.OpenConnection();
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
                return;
            }
            Console.WriteLine("Connected to the SQL server...");

            TcpListener listener = null;

            try
            {
                // Start the server on localhost (for now...).
                listener = new TcpListener(IPAddress.Parse("0.0.0.0"), 1337);
                listener.Start();
                Console.WriteLine("DVTA Server Started...");

                while(true)
                {
                    TcpClient client = listener.AcceptTcpClient();
                    Console.WriteLine("Accepted new connection from a client...");  //Should probably log the IP here...too lazy to do it now.

                    Thread t = new Thread(ProcessClientRequest);
                    t.Start(client);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            finally
            {
                // Stop the server.
                if (null != listener)
                {
                    listener.Stop();
                }
                // Close the DB connection.
                dBAccess.closeConnection();
            }
        }
    }
}
