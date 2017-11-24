using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using log4net;
using System.Globalization;

namespace SharpFtpServer
{
    public class ClientConnection : IDisposable
    {
        private class DataConnectionOperation
        {
            public Func<NetworkStream, string, string> Operation { get; set; }
            public string Arguments { get; set; }
        }

        ILog _log = LogManager.GetLogger(typeof(ClientConnection));

        private static Encoding Default_FTP_Enc = Encoding.GetEncoding(950);


        #region Copy Stream Implementations

        private static long CopyStream(Stream input, Stream output, int bufferSize)
        {
            byte[] buffer = new byte[bufferSize];
            int count = 0;
            long total = 0;

            while ((count = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, count);
                total += count;
            }

            return total;
        }

        private static long CopyStreamAscii(Stream input, Stream output, int bufferSize)
        {
            char[] buffer = new char[bufferSize];
            int count = 0;
            long total = 0;
            //ASCII
            using (StreamReader rdr = new StreamReader(input, Encoding.ASCII))
            {
                using (StreamWriter wtr = new StreamWriter(output, Encoding.ASCII))
                {
                    while ((count = rdr.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        wtr.Write(buffer, 0, count);
                        total += count;
                    }
                }
            }

            return total;
        }

        private long CopyStream(Stream input, Stream output)
        {
            Stream limitedStream = output; // new RateLimitingStream(output, 131072, 0.5);

            if (_connectionType == TransferType.Image)
            {
                return CopyStream(input, limitedStream, 4096);
            }
            else
            {
                return CopyStreamAscii(input, limitedStream, 4096);
            }
        }

        #endregion

        #region Enums

        private enum TransferType
        {
            Ascii,
            Ebcdic,
            Image,
            Local,
        }

        private enum FormatControlType
        {
            NonPrint,
            Telnet,
            CarriageControl,
        }

        private enum DataConnectionType
        {
            Passive,
            Active,
        }

        private enum FileStructureType
        {
            File,
            Record,
            Page,
        }

        #endregion


        private bool _disposed = false;

        private TcpListener _passiveListener;

        private TcpClient _controlClient;
        private TcpClient _dataClient;

        private NetworkStream _controlStream;
        // private StreamReader _controlReader;
        private StreamWriter _controlWriter;

        private TransferType _connectionType = TransferType.Ascii;
        private FormatControlType _formatControlType = FormatControlType.NonPrint;
        private DataConnectionType _dataConnectionType = DataConnectionType.Active;
        private FileStructureType _fileStructureType = FileStructureType.File;

        private string _username;
        private string _root;
        private string _currentDirectory;
        private IPEndPoint _dataEndpoint;
        private IPEndPoint _remoteEndPoint;

        private X509Certificate _cert = null;
        private SslStream _sslStream=null;

        private string _clientIP;

        private User _currentUser;

        private List<string> _validCommands;

        public ClientConnection(TcpClient client)
        {
            _controlClient = client;

            _validCommands = new List<string>();
        }

        private string CheckUser()
        {
            if (_currentUser == null)
            {
                return "530 Not logged in";
            }

            return null;
        }
        private static void convbytes()
        {
            // Define a byte array.
            byte[] bytes = { 2, 4, 6, 8, 10, 12, 14, 16, 18, 20 };
            Console.WriteLine("The byte array: ");
            Console.WriteLine("   {0}\n", BitConverter.ToString(bytes));

            // Convert the array to a base 64 sring.
            String s = Convert.ToBase64String(bytes);
            Console.WriteLine("The base 64 string:\n   {0}\n", s);

            // Restore the byte array.
            byte[] newBytes = Convert.FromBase64String(s);
            Console.WriteLine("The restored byte array: ");
            Console.WriteLine("   {0}\n", BitConverter.ToString(newBytes));
        }
        private static string base64(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
        private static byte[] base642bytes(string s)
        {
            return Convert.FromBase64String(s);
        }
        private String[] Read()
        {
            byte[] messageBytes = new byte[8192];
            int bytesRead = 0;
            if (_sslStream != null)
            {
                bytesRead = _sslStream.Read(messageBytes, 0, 8192);
                string strMessage_ = clientEnc.GetString(messageBytes, 0, bytesRead).Trim();
                string[] messages_ = strMessage_.Split('\n');
                for (int i = 0; i < messages_.Length; i++)
                {
                    messages_[i] = messages_[i].Trim();
                }
                return messages_;
            }
            else
            {
                NetworkStream clientStream = _controlClient.GetStream();
                bytesRead = clientStream.Read(messageBytes, 0, 8192);
                string strMessage = clientEnc.GetString(messageBytes, 0, bytesRead).Trim();
#if DEBUG
                Console.WriteLine("C:" + strMessage);
#else
 
#endif
                if (strMessage.Contains("LSIT -a")) strMessage = "LIST";
                string[] messages_ = strMessage.Split('\n');
                for (int i = 0; i < messages_.Length; i++)
                {
                    messages_[i] = messages_[i].Trim();
                }
                return messages_;
            }
        }
        private void Write(String strMessage)
        {
            if (_sslStream != null)
            {
                byte[] buffer = System.Text.Encoding.UTF8.GetBytes(strMessage + "\r\n");
                _sslStream.Write(buffer, 0, buffer.Length);
                _sslStream.Flush();
            }
            else
            {
                byte[] buffer = System.Text.Encoding.UTF8.GetBytes(strMessage + "\r\n");
                _controlStream.Write(buffer, 0, buffer.Length);
                _controlStream.Flush();
#if DEBUG
                Console.WriteLine("S:" + strMessage);
#else
  
#endif

            }
        }
        private Encoding clientEnc = Default_FTP_Enc;
        public void HandleClient(object obj)
        {
            _remoteEndPoint = (IPEndPoint)_controlClient.Client.RemoteEndPoint;
            
            _clientIP = _remoteEndPoint.Address.ToString();
            
            _controlStream = _controlClient.GetStream();

           // _controlReader = new StreamReader(_controlStream, Encoding.Default);
            _controlWriter = new StreamWriter(_controlStream);

           Write("220-Service Ready\r\n FTP SERVER\r\n220 end.");
            _validCommands.AddRange(new string[] { "AUTH", "USER", "PASS", "QUIT", "HELP", "NOOP" });

            

            _dataClient = new TcpClient();

            string renameFrom = null;
            string[] lines = null ;
            string line;
            try
            {
                //  while ((line = _controlReader.ReadLine()) != null)
                 while ((lines = Read()) != null)
                {
                    for (int i = lines.Length-1; i < lines.Length; i++)
                    {
                        line = lines[i];
                      
                        if (line.Trim().Equals(""))
                        {
                            Write("200 ok go ahead.");
                            continue;
                        }
                        if (line.StartsWith("OPTS UTF8 ON"))
                        {
                            clientEnc = Encoding.UTF8;
                            Write("200 Command okay.");
                            continue;
                        }
                        else if (line.StartsWith("opts utf8 on"))
                        {
                            clientEnc = Default_FTP_Enc;
                            Write("502 no impl.");
                            continue;
                        }
                        string response = null;

                        string[] command = line.Split(' ');

                        string cmd = command[0].ToUpperInvariant();
                        string arguments = command.Length > 1 ? line.Substring(command[0].Length + 1) : null;

                        if (arguments != null && arguments.Trim().Length == 0)
                        {
                            arguments = null;
                        }

                        LogEntry logEntry = new LogEntry
                        {
                            Date = DateTime.Now,
                            CIP = _clientIP,
                            CSUriStem = arguments
                        };

                        if (!_validCommands.Contains(cmd))
                        {
                            response = CheckUser();
                        }

                        if (cmd != "RNTO")
                        {
                            renameFrom = null;
                        }

                        if (response == null)
                        {

                            switch (cmd)
                            {
                                case "USER":
                                    response = User(arguments);
                                    break;
                                case "PASS":
                                    response = Password(arguments);
                                    logEntry.CSUriStem = "******";
                                    break;
                                case "CWD":
                                    response = ChangeWorkingDirectory(arguments);
                                    break;
                                case "CDUP":
                                    response = ChangeWorkingDirectory("..");
                                    break;
                                case "QUIT":
                                    response = "221 Service closing control connection";
                                    break;
                                case "REIN":
                                    _currentUser = null;
                                    _username = null;
                                    _passiveListener = null;
                                    _dataClient = null;

                                    response = "220 Service ready for new user";
                                    break;
                                case "PORT":

                                    response = Port(arguments);
                                    logEntry.CPort = _dataEndpoint.Port.ToString();
                                    break;
                                case "PASV":
                                    response = "502 Command not implemented";
                                    response = Passive();
                                    logEntry.SPort = ((IPEndPoint)_passiveListener.LocalEndpoint).Port.ToString();
                                    break;
                                case "TYPE":
                                    response = Type(command[1], command.Length == 3 ? command[2] : null);
                                    logEntry.CSUriStem = command[1];
                                    break;
                                case "STRU":
                                    response = Structure(arguments);
                                    break;
                                case "MODE":
                                    response = Mode(arguments);
                                    break;
                                case "RNFR":
                                    renameFrom = arguments;
                                    response = "350 Requested file action pending further information";
                                    break;
                                case "RNTO":
                                    response = Rename(renameFrom, arguments);
                                    break;
                                case "DELE":
                                    response = Delete(arguments);
                                    break;
                                case "RMD":
                                    response = RemoveDir(arguments);
                                    break;
                                case "MKD":
                                    response = CreateDir(arguments);
                                    break;
                                case "PWD":
                                    response = PrintWorkingDirectory();
                                    break;
                                case "RETR":
                                    response = Retrieve(arguments);
                                    logEntry.Date = DateTime.Now;
                                    break;
                                case "STOR":
                                    if (arguments.Contains("?"))
                                    {
                                        response = "501 Invalid character in file name BadFileName";
                                    }
                                    else
                                    {
                                        response = Store(arguments);
                                        logEntry.Date = DateTime.Now;
                                    }
                                    break;
                                case "STOU":
                                    response = StoreUnique();
                                    logEntry.Date = DateTime.Now;
                                    break;
                                case "APPE":
                                    response = Append(arguments);
                                    logEntry.Date = DateTime.Now;
                                    break;
                                case "LIST":
                                    response = List(arguments ?? _currentDirectory);
                                    logEntry.Date = DateTime.Now;
                                    break;
                                case "SYST":
                                    response = "215 UNIX Type: L8";
                                    break;
                                case "NOOP":
                                    response = "200 ok";
                                    break;
                                case "ACCT":
                                    response = "200 OK";
                                    break;
                                case "ALLO":
                                    response = "200 OK";
                                    break;
                                case "NLST":
                                    response = "502 Command not implemented";
                                    break;
                                case "SITE":
                                    response = "502 Command not implemented";
                                    break;
                                case "STAT":
                                    response = "502 Command not implemented";
                                    break;
                                case "HELP":
                                    response = "502 Command not implemented";
                                    break;
                                case "SMNT":
                                    response = "502 Command not implemented";
                                    break;
                                case "REST":
                                    response = "502 Command not implemented";
                                    break;
                                case "ABOR":
                                    response = "502 Command not implemented";
                                    break;

                                // Extensions defined by rfc 2228
                                case "AUTH":
                                    response = Auth(arguments);
                                    break;

                                // Extensions defined by rfc 2389
                                case "FEAT":
                                    response = FeatureList();
                                    break;
                                case "OPTS":
                                    response = Options(arguments);
                                    break;

                                // Extensions defined by rfc 3659
                                case "MDTM":
                                    response = FileModificationTime(arguments);
                                    break;
                                case "SIZE":
                                    response = FileSize(arguments);
                                    break;

                                // Extensions defined by rfc 2428
                                case "EPRT":
                                    response = EPort(arguments);
                                    logEntry.CPort = _dataEndpoint.Port.ToString();
                                    break;
                                case "EPSV":
                                    response = EPassive();
                                    logEntry.SPort = ((IPEndPoint)_passiveListener.LocalEndpoint).Port.ToString();
                                    break;

                                default:
                                    response = "502 Command not implemented";
                                    break;
                            }
                        }

                        logEntry.CSMethod = cmd;
                        logEntry.CSUsername = _username;
                        logEntry.SCStatus = response.Substring(0, response.IndexOf(' '));

                        _log.Info(logEntry);

                        if (_controlClient == null || !_controlClient.Connected)
                        {
                            goto outerloop;
                        }
                        else
                        {
                            Write(response);


                            if (response.StartsWith("221"))
                            {
                                goto outerloop;
                            }

                            if (cmd == "AUTH")
                            {
                                Console.WriteLine("no impl!");

                                _cert = new X509Certificate("server.cer");

                                _sslStream = new SslStream(_controlStream);

                                _sslStream.AuthenticateAsServer(_cert);

                                // _controlReader = new StreamReader(_sslStream);
                                // _controlWriter = new StreamWriter(_sslStream);
                            }
                        }
                    }
                }
                outerloop: int outerloop_cnt = 0;
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
            }

            Dispose();
        }

        private bool IsPathValid(string path)
        {
            return path.StartsWith(_root);
        }

        private string NormalizeFilename(string path)
        {
            if (path == null)
            {
                path = string.Empty;
            }

            if (path == "/")
            {
                return _root;
            }
            else if (path.StartsWith("/"))
            {
                path = new FileInfo(Path.Combine(_root, path.Substring(1))).FullName;
            }
            else
            {
                path = new FileInfo(Path.Combine(_currentDirectory, path)).FullName;
            }

            return IsPathValid(path) ? path : null;
        }

        #region FTP Commands

        private string FeatureList()
        {

            /*
            _controlWriter.WriteLine("211- Extensions supported:");
            _controlWriter.WriteLine(" MDTM");
            _controlWriter.WriteLine(" SIZE");
            return "211 End";*/
            String ret =
@"211-Extensions supported:
 MDTM
 SIZE
 UTF8
 LANG EN;ZH*
211 End";
            /*String ret= 
@"211 -Extensions supported:
 EPRT
 IDLE
 MDTM
 SIZE
 MFMT
 REST STREAM
 MLST type *; size *; sizd *; modify *; UNIX.mode *; UNIX.uid *; UNIX.gid *; unique *;
 MLSD
 AUTH TLS
 PBSZ
 PROT
 TVFS
 ESTA
 PASV
 EPSV
 SPSV
 ESTP
211 End.";*/
            return ret;
        }

        private string Options(string arguments)
        {
            if (arguments.ToUpper().StartsWith("UTF8")||arguments.ToUpper().StartsWith("UTF-8"))
            {
                Console.WriteLine("200  UTF8 support on");
                clientEnc = Encoding.UTF8;
                return "200 UTF8 support on.";
            }
            else
            {
                return "200 Looks good to me...";
            }
        }

        private string Auth(string authMode)
        {
            if (authMode == "TLS")
            {
                return "234 Enabling TLS Connection";
            }
            else
            {
                return "504 Unrecognized AUTH mode";
            }
        }

        private string User(string username)
        {
            _username = username.Trim();
            _currentUser = UserStore.Validate(_username);
            if (_currentUser != null)
            {
                _root = _currentUser.HomeDir;
                _currentDirectory = _root;
                return "230 User logged in";
            }
            else
            {
                return "331 Username ok, need password";
            }
        }

        private string Password(string password)
        {
            _currentUser = UserStore.Validate(_username, password);

            if (_currentUser != null)
            {
                _root = _currentUser.HomeDir;
                _currentDirectory = _root;

                return "230 User logged in cool";

            }
            else
            {
                return "530 Not logged in";
            }
        }

        private string ChangeWorkingDirectory(string pathname)
        {
            if (pathname == "/")
            {
                _currentDirectory = _root;
            }
            else
            {
                string newDir;

                if (pathname.StartsWith("/"))
                {
                    pathname = pathname.Substring(1).Replace('/', '\\');
                    newDir = Path.Combine(_root, pathname);
                }
                else
                {
                    pathname = pathname.Replace('/', '\\');
                    newDir = Path.Combine(_currentDirectory, pathname);
                }

                if (Directory.Exists(newDir))
                {
                    _currentDirectory = new DirectoryInfo(newDir).FullName;

                    if (!IsPathValid(_currentDirectory))
                    {
                        _currentDirectory = _root;
                    }
                }
                else
                {
                    _currentDirectory = _root;
                }
            }

            return "250 Changed to new directory";
        }

        private string Port(string hostPort)
        {
            _dataConnectionType = DataConnectionType.Active;

            string[] ipAndPort = hostPort.Split(',');

            byte[] ipAddress = new byte[4];
            byte[] port = new byte[2];

            for (int i = 0; i < 4; i++)
            {
                ipAddress[i] = Convert.ToByte(ipAndPort[i]);
            }

            for (int i = 4; i < 6; i++)
            {
                port[i - 4] = Convert.ToByte(ipAndPort[i]);
            }

            if (BitConverter.IsLittleEndian)
                Array.Reverse(port);
            IPAddress __ipAddress = new IPAddress(ipAddress);
            //Int32 __port = BitConverter.ToInt32(port, 0);
            Int32 __port = port[1] * 256 + port[0];
            _dataEndpoint = new IPEndPoint(__ipAddress, __port);

            return "200 Data Connection Established";
        }

        private string EPort(string hostPort)
        {
            _dataConnectionType = DataConnectionType.Active;

            char delimiter = hostPort[0];

            string[] rawSplit = hostPort.Split(new char[] { delimiter }, StringSplitOptions.RemoveEmptyEntries);

            char ipType = rawSplit[0][0];

            string ipAddress = rawSplit[1];
            string port = rawSplit[2];

            _dataEndpoint = new IPEndPoint(IPAddress.Parse(ipAddress), int.Parse(port));

            return "200 Data Connection Established";
        }

        private string Passive()
        {
            _dataConnectionType = DataConnectionType.Passive;

            IPAddress localIp = ((IPEndPoint)_controlClient.Client.LocalEndPoint).Address;

            _passiveListener = new TcpListener(localIp, 0);
            _passiveListener.Start();

            IPEndPoint passiveListenerEndpoint = (IPEndPoint)_passiveListener.LocalEndpoint;

            byte[] address = passiveListenerEndpoint.Address.GetAddressBytes();
            short port = (short)passiveListenerEndpoint.Port;

            byte[] portArray = BitConverter.GetBytes(port);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(portArray);

            return string.Format("227 Entering Passive Mode ({0},{1},{2},{3},{4},{5})", address[0], address[1], address[2], address[3], portArray[0], portArray[1]);
        }

        private string EPassive()
        {
            _dataConnectionType = DataConnectionType.Passive;

            IPAddress localIp = ((IPEndPoint)_controlClient.Client.LocalEndPoint).Address;

            _passiveListener = new TcpListener(localIp, 0);
            _passiveListener.Start();

            IPEndPoint passiveListenerEndpoint = (IPEndPoint)_passiveListener.LocalEndpoint;

            return string.Format("229 Entering Extended Passive Mode (|||{0}|)", passiveListenerEndpoint.Port);
        }

        private string Type(string typeCode, string formatControl)
        {
            switch (typeCode.ToUpperInvariant())
            {
                case "A":
                   _connectionType = TransferType.Ascii;
                    break;
                case "I":
                    _connectionType = TransferType.Image;
                    break;
                default:
                    return "504 Command not implemented for that parameter";
            }

            if (!string.IsNullOrWhiteSpace(formatControl))
            {
                switch (formatControl.ToUpperInvariant())
                {
                    case "N":
                        _formatControlType = FormatControlType.NonPrint;
                        break;
                    default:
                        return "504 Command not implemented for that parameter";
                }
            }

            return string.Format("200 Type set to {0}", _connectionType);
        }

        private string Delete(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (File.Exists(pathname))
                {
                    File.Delete(pathname);
                }
                else
                {
                    return "550 File Not Found";
                }

                return "250 Requested file action okay, completed";
            }

            return "550 File Not Found";
        }

        private string RemoveDir(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (Directory.Exists(pathname))
                {
                    Directory.Delete(pathname);
                }
                else
                {
                    return "550 Directory Not Found";
                }

                return "250 Requested file action okay, completed";
            }

            return "550 Directory Not Found";
        }

        private string CreateDir(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (!Directory.Exists(pathname))
                {
                    Directory.CreateDirectory(pathname);
                }
                else
                {
                    return "550 Directory already exists";
                }

                return "250 Requested file action okay, completed";
            }

            return "550 Directory Not Found";
        }

        private string FileModificationTime(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (File.Exists(pathname))
                {
                    return string.Format("213 {0}", File.GetLastWriteTime(pathname).ToString("yyyyMMddHHmmss.fff"));
                }
            }

            return "550 File Not Found";
        }

        private string FileSize(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (File.Exists(pathname))
                {
                    long length = 0;

                    using (FileStream fs = File.Open(pathname, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        length = fs.Length;
                    }

                    return string.Format("213 {0}", length);
                }
            }

            return "550 File Not Found";
        }

        private string Retrieve(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                if (File.Exists(pathname))
                {
                    var state = new DataConnectionOperation { Arguments = pathname, Operation = RetrieveOperation };

                    SetupDataConnectionOperation(state);

                    return string.Format("150 Opening {0} mode data transfer for RETR", _dataConnectionType);
                }
            }

            return "550 File Not Found";
        }

        private string Store(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                var state = new DataConnectionOperation { Arguments = pathname, Operation = StoreOperation };

                SetupDataConnectionOperation(state);

                return string.Format("150 Opening {0} mode data transfer for STOR", _dataConnectionType);
            }

            return "450 Requested file action not taken";
        }

        private string Append(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                var state = new DataConnectionOperation { Arguments = pathname, Operation = AppendOperation };

                SetupDataConnectionOperation(state);

                return string.Format("150 Opening {0} mode data transfer for APPE", _dataConnectionType);
            }

            return "450 Requested file action not taken";
        }

        private string StoreUnique()
        {
            string pathname = NormalizeFilename(new Guid().ToString());

            var state = new DataConnectionOperation { Arguments = pathname, Operation = StoreOperation };

            SetupDataConnectionOperation(state);

            return string.Format("150 Opening {0} mode data transfer for STOU", _dataConnectionType);
        }

        private string PrintWorkingDirectory()
        {
            string current = _currentDirectory.Replace(_root, string.Empty).Replace('\\', '/');

            if (current.Length == 0)
            {
                current = "/";
            }

            return string.Format("257 \"{0}\" is current directory.", current); ;
        }

        private string List(string pathname)
        {
            pathname = NormalizeFilename(pathname);

            if (pathname != null)
            {
                var state = new DataConnectionOperation { Arguments = pathname, Operation = ListOperation };

                SetupDataConnectionOperation(state);

                return string.Format("150 Opening {0} mode data transfer for LIST", _dataConnectionType);
            }

            return "450 Requested file action not taken";
        }

        private string Structure(string structure)
        {
            switch (structure)
            {
                case "F":
                    _fileStructureType = FileStructureType.File;
                    break;
                case "R":
                case "P":
                    return string.Format("504 STRU not implemented for \"{0}\"", structure);
                default:
                    return string.Format("501 Parameter {0} not recognized", structure);
            }

            return "200 Command OK";
        }

        private string Mode(string mode)
        {
            if (mode.ToUpperInvariant() == "S")
            {
                return "200 OK";
            }
            else
            {
                return "504 Command not implemented for that parameter";
            }
        }

        private string Rename(string renameFrom, string renameTo)
        {
            if (string.IsNullOrWhiteSpace(renameFrom) || string.IsNullOrWhiteSpace(renameTo))
            {
                return "450 Requested file action not taken";
            }

            renameFrom = NormalizeFilename(renameFrom);
            renameTo = NormalizeFilename(renameTo);

            if (renameFrom != null && renameTo != null)
            {
                if (File.Exists(renameFrom))
                {
                    File.Move(renameFrom, renameTo);
                }
                else if (Directory.Exists(renameFrom))
                {
                    Directory.Move(renameFrom, renameTo);
                }
                else
                {
                    return "450 Requested file action not taken";
                }

                return "250 Requested file action okay, completed";
            }

            return "450 Requested file action not taken";
        }

        #endregion

        #region DataConnection Operations

        private void HandleAsyncResult(IAsyncResult result)
        {
            if (_dataConnectionType == DataConnectionType.Active)
            {
                _dataClient.EndConnect(result);
            }
            else
            {
                _dataClient = _passiveListener.EndAcceptTcpClient(result);
            }
        }

        private void SetupDataConnectionOperation(DataConnectionOperation state)
        {
            if (_dataConnectionType == DataConnectionType.Active)
            {
                _dataClient = new TcpClient(_dataEndpoint.AddressFamily);
                _dataClient.BeginConnect(_dataEndpoint.Address, _dataEndpoint.Port, DoDataConnectionOperation, state);
            }
            else
            {
                _passiveListener.BeginAcceptTcpClient(DoDataConnectionOperation, state);
            }
        }

        private void DoDataConnectionOperation(IAsyncResult result)
        {
            HandleAsyncResult(result);

            DataConnectionOperation op = result.AsyncState as DataConnectionOperation;

            string response;

            using (NetworkStream dataStream = _dataClient.GetStream())
            {
                response = op.Operation(dataStream, op.Arguments);
            }

            _dataClient.Close();
            _dataClient = null;

            Write(response);
            
        }

        private string RetrieveOperation(NetworkStream dataStream, string pathname)
        {
            long bytes = 0;

            using (FileStream fs = new FileStream(pathname, FileMode.Open, FileAccess.Read))
            {
                bytes = CopyStream(fs, dataStream);
            }

            return "226 Closing data connection, file transfer successful";
        }

        private string StoreOperation(NetworkStream dataStream, string pathname)
        {
            long bytes = 0;
            

            using (FileStream fs = new FileStream(pathname, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None, 4096, FileOptions.SequentialScan))
            {
                bytes = CopyStream(dataStream, fs);
            }

            LogEntry logEntry = new LogEntry
            {
                Date = DateTime.Now,
                CIP = _clientIP,
                CSMethod = "STOR",
                CSUsername = _username,
                SCStatus = "226",
                CSBytes = bytes.ToString()
            };

            _log.Info(logEntry);

            return "226 Closing data connection, file transfer successful";
        }

        private string AppendOperation(NetworkStream dataStream, string pathname)
        {
            long bytes = 0;

            using (FileStream fs = new FileStream(pathname, FileMode.Append, FileAccess.Write, FileShare.None, 4096, FileOptions.SequentialScan))
            {
                bytes = CopyStream(dataStream, fs);
            }

            LogEntry logEntry = new LogEntry
            {
                Date = DateTime.Now,
                CIP = _clientIP,
                CSMethod = "APPE",
                CSUsername = _username,
                SCStatus = "226",
                CSBytes = bytes.ToString()
            };

            _log.Info(logEntry);

            return "226 Closing data connection, file transfer successful";
        }

        private string ListOperation(NetworkStream dataStream, string pathname)
        {
            //StreamWriter dataWriter = new StreamWriter(dataStream, Encoding.ASCII);
            StreamWriter dataWriter = new StreamWriter(dataStream, clientEnc);


            //IEnumerable<string> directories = Directory.EnumerateDirectories(pathname);
            
            DirectoryInfo directories = new DirectoryInfo(pathname);
            if(!directories.Exists) return "502 Transfer complete";
            foreach (DirectoryInfo d  in directories.GetDirectories())
            {
               // DirectoryInfo d = new DirectoryInfo(dir);

                string date = d.LastWriteTime < DateTime.Now - TimeSpan.FromDays(180) ?
                    d.LastWriteTime.ToString("MMM dd  yyyy", CultureInfo.CreateSpecificCulture("en-US")) :
                    
                    d.LastWriteTime.ToString("MMM dd HH:mm", CultureInfo.CreateSpecificCulture("en-US"));

                string line = string.Format("drwxr-xr-x    2 2003     2003     {0,8} {1} {2}", "4096", date, d.Name);

                dataWriter.WriteLine(line);
                dataWriter.Flush();
            }

           //IEnumerable<string> files = Directory.EnumerateFiles(pathname);

            foreach (FileInfo f in directories.GetFiles())
            {
                //FileInfo f = new FileInfo(file);

                string date = f.LastWriteTime < DateTime.Now - TimeSpan.FromDays(180) ?
                    f.LastWriteTime.ToString("MMM dd  yyyy", CultureInfo.CreateSpecificCulture("en-US")) :
                    f.LastWriteTime.ToString("MMM dd HH:mm", CultureInfo.CreateSpecificCulture("en-US"));
                    //f.LastWriteTime.ToString("MMM dd  yyyy");
                string line = string.Format("-rw-r--r--    2 2003     2003     {0,8} {1} {2}", f.Length, date, f.Name);
                

                dataWriter.WriteLine(line);
                dataWriter.Flush();
            }

            LogEntry logEntry = new LogEntry
            {
                Date = DateTime.Now,
                CIP = _clientIP,
                CSMethod = "LIST",
                CSUsername = _username,
                SCStatus = "226"
            };

            _log.Info(logEntry);

            return "226 Transfer complete";
        }

        #endregion

        #region IDisposable

                public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (_controlClient != null)
                    {
                        _controlClient.Close();
                    }

                    if (_dataClient != null)
                    {
                        _dataClient.Close();
                    }

                    if (_controlStream != null)
                    {
                        _controlStream.Close();
                    }
                    /*
                    if (_controlReader != null)
                    {
                        _controlReader.Close();
                    }*/
                    /*
                    if (_controlWriter != null)
                    {
                        _controlWriter.Close();
                    }*/
                }
            }

            _disposed = true;
        }
        
        #endregion
    }
}
/*
 * 200 Command okay.
      421 Service not available, closing control connection.
      500 Syntax error, command unrecognized.
      501 Syntax error in parameters or arguments.
      502 Command not implemented.
*/