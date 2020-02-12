using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using ServerDataHandling;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
using System.Xml;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;

namespace DVTA_CTF_Server
{
    class Handler
    {
        // This function is responsible for handling login requests. It will check the database for the credentials and return a users.xml file if the creds are valid.
        // The returned users.xml file is dependant on user type. An admin will get a different users.xml file than a normal user. 
        public static void HandleLogin(TcpClient client, string arguments)
        {
            string[] creds = new string[2];
            XmlDocument allusers;
            SqlDataReader data;
            NetworkStream stream = client.GetStream();

            // TODO check the way it gets split.
            creds = arguments.Split(new char[] { ' ' }, 2);
            Console.WriteLine("Login attempt from %s with hash: %s", creds[0], Crypto.HashPassword(creds[1]));
            data = Server.dBAccess.checkLogin(creds[0], Crypto.HashPassword(creds[1]));

            if(data.HasRows)
            {
                Console.WriteLine("Login successful.\nSending users.xml...");
                allusers = Server.dBAccess.GetAllUsers();
                XmlNode clientHash = allusers.CreateElement("clientHash");

                // Checks if the user is an admin. Sends a different client hash based on that.
                if (1 == (int)data.GetValue(4))
                {
                    clientHash.InnerText = "ADMINHASH";
                }
                else
                {
                    clientHash.InnerText = "CLIENTHASH";
                }
                allusers.DocumentElement.InsertBefore(clientHash, allusers.DocumentElement.FirstChild);

                // Convert the Xml Document to a String.
                XmlTextWriter xmltxt = new XmlTextWriter(new StringWriter());
                string responseString;
                using (StringWriter sw = new StringWriter())
                {
                    using (XmlTextWriter tx = new XmlTextWriter(sw))
                    {
                        allusers.WriteTo(tx);
                        responseString = sw.ToString();
                    }
                }
                byte[] response = Encoding.UTF8.GetBytes(responseString);

                stream.Write(response, 0, response.Length);
            }
            else
            {
                Console.WriteLine("Login failed.");
                byte[] response = Encoding.UTF8.GetBytes("InvalidCredentials");
                stream.Write(response, 0, response.Length);
            }

            client.Close();
        }


        // This function is responsible for registering new users.
        public static void HandleRegister(TcpClient client, string arguments)
        {
            string[] userinfo = new string[3];
            NetworkStream stream = client.GetStream();

            // TODO check the way it gets split.
            userinfo = arguments.Split(new char[] { ' ' }, 3);
            Console.WriteLine("New user registering with username %s and email %s.", userinfo[0], userinfo[2]);

            if(Server.dBAccess.RegisterUser(userinfo[0], userinfo[1], userinfo[2]))
            {
                byte[] response = Encoding.UTF8.GetBytes("Success");
                stream.Write(response, 0, response.Length);
            }
            else
            {
                byte[] response = Encoding.UTF8.GetBytes("Failed");
                stream.Write(response, 0, response.Length);
            }

            client.Close();
        }

        // This function serves the clients with the xml containing application data.
        // It should serve a new client the first flag also.
        public static void HandleDownloadUserXML(TcpClient client, string arguments)
        {
            NetworkStream stream = client.GetStream();
            Console.WriteLine("Serving data to user %s", arguments);
            byte[] response = Encoding.UTF8.GetBytes(Server.dBAccess.GetExpenses(arguments));
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        // Receives the user's local xml after the user clicks logout. It stores the data found the in the database.
        public static void HandleUploadUserXML(TcpClient client, string arguments)
        {
            string[] data = new string[2];
            data = arguments.Split(new char[] { ' ' }, 2);

            NetworkStream stream = client.GetStream();
            Console.WriteLine("Receiving data from user %s", data[0]);
            Server.dBAccess.AddExpenses(data[0], data[1]);

            client.Close();
        }

        // Undocumented method that enables login using only the password hash.
        // Basically, the same as login...it does not do the hashing.
        public static void HandlePassTheHashLogin(TcpClient client, string arguments)
        {
            string[] creds = new string[2];
            XmlDocument allusers;
            SqlDataReader data;
            NetworkStream stream = client.GetStream();

            // TODO check the way it gets split.
            creds = arguments.Split(new char[] { ' ' }, 2);
            Console.WriteLine("Login attempt from %s with hash: %s", creds[0], creds[1]);
            data = Server.dBAccess.checkLogin(creds[0], creds[1]);

            if (data.HasRows)
            {
                Console.WriteLine("Login successful.\nSending users.xml...");
                allusers = Server.dBAccess.GetAllUsers();
                XmlNode clientHash = allusers.CreateElement("clientHash");

                // Checks if the user is an admin. Sends a different client hash based on that.
                if (1 == (int)data.GetValue(4))
                {
                    clientHash.InnerText = "ADMINHASH";
                }
                else
                {
                    clientHash.InnerText = "CLIENTHASH";
                }
                allusers.DocumentElement.InsertBefore(clientHash, allusers.DocumentElement.FirstChild);

                // Convert the Xml Document to a String.
                XmlTextWriter xmltxt = new XmlTextWriter(new StringWriter());
                string responseString;
                using (StringWriter sw = new StringWriter())
                {
                    using (XmlTextWriter tx = new XmlTextWriter(sw))
                    {
                        allusers.WriteTo(tx);
                        responseString = sw.ToString();
                    }
                }
                byte[] response = Encoding.UTF8.GetBytes(responseString);

                stream.Write(response, 0, response.Length);
            }
            else
            {
                Console.WriteLine("Login failed.");
                byte[] response = Encoding.UTF8.GetBytes("InvalidCredentials");
                stream.Write(response, 0, response.Length);
            }

            client.Close();
        }

        public static void HandleViewProfile(TcpClient client, string arguments)
        {
            NetworkStream stream = client.GetStream();
            Console.WriteLine("Viewing profile of user %s", arguments);
            byte[] response = Encoding.UTF8.GetBytes(Server.dBAccess.ViewProfile(arguments));
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        public static void HandleTestDBConnection(TcpClient client, string arguments)
        {
            string[] data = new string[2];

            string responseString = String.Empty;
            string server = String.Empty;
            string database = String.Empty;

            data = arguments.Split(new char[] { ' ' }, 2);

            if ("ADMINHASH" != data[0])
            {
                responseString = "You are not an admin!";
            }
            else
            {
                XmlDocument doc = new XmlDocument();
                try
                {
                    // This looks a bit lame, but this is the easiest way I can create an XML injection.
                    doc.LoadXml("<?xml version='1.0' encoding='utf-8'?><data><server>127.0.0.1</server><database>" + data[1] + "</database></data>");

                    foreach (XmlNode node in doc.DocumentElement.ChildNodes)
                    {
                        if ("server" == node.Name)
                        {
                            //Console.WriteLine(node.InnerText);
                            server = node.InnerText;
                        }
                        else if ("database" == node.Name)
                        {
                            //Console.WriteLine(node.InnerText);
                            database = node.InnerText;
                        }
                    }

                    Console.WriteLine("Testing DB connection to {0}\\{2}", server, database);

                    try
                    {
                        DBAccessClass testAccess = new DBAccessClass();
                        testAccess.OpenTestConnection(server, database);

                        responseString = "Successfully connected to " + server + "\\" + database;
                        Console.WriteLine(responseString);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        responseString = e.ToString();
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    responseString = e.ToString();
                }
            }

            NetworkStream stream = client.GetStream();
            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        // Handles a request to back up the flag to the ftp server. It expects 3 arguments: Admin hash, username and encryption/decryption key.
        public static void HandleBackupFiles(TcpClient client, string arguments)
        {
            string[] data = new string[3];
            string responseString = string.Empty;
            data = arguments.Split(new char[] { ' ' }, 3);

            if ("ADMINHASH" != data[0])
            {
                responseString = "You are not an admin!";
            }
            else
            {
                string encryptedPass = Server.dBAccess.GetFTPCredentials();
                if (encryptedPass == string.Empty)
                {
                    responseString = "Something went wrong!";
                }
                else
                {
                    string password = Crypto.DecryptPassword(encryptedPass, data[2]);

                    using (System.Net.WebClient ftpclient = new System.Net.WebClient())
                    {
                        try
                        {
                            ftpclient.Credentials = new System.Net.NetworkCredential(data[1], password);
                            ftpclient.UploadFile("ftp://localhost/" + new FileInfo("flag.txt").Name, "STOR", "flag.txt");

                            responseString = "Success";
                        }
                        catch (Exception ftpexc)
                        {
                            Console.WriteLine(ftpexc);
                            responseString = "Something went wrong!";
                        }
                    }
                }
            }

            NetworkStream stream = client.GetStream();
            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        // This function Handles checking the logs. It expects 2 arguments: the admin hash and serialized data in base64 encoded format.
        public static void HandleCheckLog(TcpClient client, string arguments)
        {
            string[] data = new string[2];
            byte[] serialData;
            string responseString = string.Empty;
            data = arguments.Split(new char[] { ' ' }, 2);

            if ("ADMINHASH" != data[0])
            {
                responseString = "You are not an admin!";
            }
            else
            {
                try
                {
                    serialData = Convert.FromBase64String(data[1]);

                    BinaryFormatter fmt = new BinaryFormatter();
                    MemoryStream stm = new MemoryStream(serialData);
                    IRunnable run = (IRunnable)fmt.Deserialize(stm);

                    responseString = run.Run();
                }
                catch(Exception e)
                {
                    responseString = e.ToString();
                }
            }

            NetworkStream stream = client.GetStream();
            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);

            client.Close();
        }

        public static void HandleUnknownCommand(TcpClient client, string arguments)
        {
            string responseString = "Unknown command! The list of available commands:\n" +
                "login <username> <password>\n" +
                "regis <username> <password> <email>\n" +
                "dlxml <username>\n" +
                "ulxml <username> <xmlfile>\n" +
                "vwprf <username>\n" +
                "pthlg <username> <hash> - Depricated! Remove it, Dave!\n";

            NetworkStream stream = client.GetStream();
            byte[] response = Encoding.UTF8.GetBytes(responseString);
            stream.Write(response, 0, response.Length);

            client.Close();
        }
    }
}
