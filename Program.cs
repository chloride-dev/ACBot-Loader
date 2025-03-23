using System;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Net;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using System.Data.Common;
using Microsoft.CSharp.RuntimeBinder;
using ACBotLoader;
using System.Reflection;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text;
using System.Runtime;



namespace ACBotLoader
{

    public class TcpClientHelper
    {
   
        public static async Task<string> RunTcpClientCommunication(ILogger logger,string host, int port, string message)
        {
            try
            {
                using (TcpClient client = new TcpClient(host, port)) 
                using (NetworkStream stream = client.GetStream()) 
                {
          
                    byte[] data = Encoding.UTF8.GetBytes(message);
                    await stream.WriteAsync(data, 0, data.Length); 

                 
                    byte[] buffer = new byte[1024];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length); 
                    string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    return response; 
                }
            }
            catch (SocketException ex)
            {
                logger.LogCritical($"Socket exception: {ex.Message}");
                return null; 
            }
            catch (Exception ex)
            {
                logger.LogCritical($"Unexpected error: {ex.Message}");
                return null; 
            }
        }
    }


    class Program
    {
        

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        
        [DllImport("kernel32.dll")]
        public static extern bool FreeLibrary(IntPtr hModule);



        public static readonly string LoaderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ACBot", "Loader");
        //public static readonly string crashRreportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "crash-reports");
        private static readonly string downloadsPath = Path.Combine(LoaderPath, "downloads");
        private static readonly string versionInfoPath = Path.Combine(LoaderPath, "versionInfo.json");
        
        private static readonly string clientPath = Path.Combine(LoaderPath, "client\\client.exe");
        private static readonly string dependenciesApiPath = Path.Combine(LoaderPath, "dependencies", "api");

        static async Task Main(string[] args)
        {

            if (!IsRunningAsAdmin())
            {
            
         
                RestartAsAdmin();
                return; 
            }


            Console.Title = "ACBot Loader";
            Console.WriteLine("\n  /$$$$$$   /$$$$$$  /$$$$$$$              /$$           /$$                                 /$$                    \r\n /$$__  $$ /$$__  $$| $$__  $$            | $$          | $$                                | $$                    \r\n| $$  \\ $$| $$  \\__/| $$  \\ $$  /$$$$$$  /$$$$$$        | $$        /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ \r\n| $$$$$$$$| $$      | $$$$$$$  /$$__  $$|_  $$_/        | $$       /$$__  $$ |____  $$ /$$__  $$ /$$__  $$ /$$__  $$\r\n| $$__  $$| $$      | $$__  $$| $$  \\ $$  | $$          | $$      | $$  \\ $$  /$$$$$$$| $$  | $$| $$$$$$$$| $$  \\__/\r\n| $$  | $$| $$    $$| $$  \\ $$| $$  | $$  | $$ /$$      | $$      | $$  | $$ /$$__  $$| $$  | $$| $$_____/| $$      \r\n| $$  | $$|  $$$$$$/| $$$$$$$/|  $$$$$$/  |  $$$$/      | $$$$$$$$|  $$$$$$/|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$      \r\n|__/  |__/ \\______/ |_______/  \\______/    \\___/        |________/ \\______/  \\_______/ \\_______/ \\_______/|__/      \r\n                                                                                                                    \r\n                                                                                                                    \r\n                                                                                                                    ");



            var loggerFactory = LoggerFactory.Create(builder =>
            {
                //builder.AddConsole();
                builder.AddSystemdConsole();
            });
            var logger = loggerFactory.CreateLogger<Program>();
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;



            //            logger.LogInformation($"Logger: {logger.GetType}");


            LoadNatives(logger);
           
   

            Directory.CreateDirectory(LoaderPath);
            Directory.CreateDirectory(downloadsPath);

            if (!File.Exists(versionInfoPath))
            {
                var defaultVersionInfo = new VersionInfo
                {
                    ClientVersion = "unknown",
                    ResourcesVersion = "unknown",
                    DependenciesVersion = "unknown"
                };
                defaultVersionInfo.Save(versionInfoPath);

            }

            

//            logger.LogInformation("Starting component update checks...");




            await CheckAndUpdate("client", "https://your.web.site/client.json", logger);
            await CheckAndUpdate("resources", "https://your.web.site/resources.json", logger);
            await CheckAndUpdate("dependencies", "https://your.web.site/dependencies.json", logger);
            await CheckAndUpdateEdgeDriverAutomatically(logger);
            Console.Title = "ACBot Loader";
            logger.LogInformation("All updates completed. Starting the server...");
            StartProxyServer(logger);
            StartHttpServer(logger);
            

            logger.LogInformation("Server started. Launching client...\n\n");

            RunClientAsAdmin(logger);

            KillEdgeDriverProcess(logger);


            Environment.Exit(0);

           // KillEdgeDriverProcess(logger);
        }

        private static async Task CheckAndUpdate(string componentName, string jsonUrl, ILogger logger)
        {
            var versionInfo = VersionInfo.Load(versionInfoPath);
            
            var json = await GetJsonFromUrl(jsonUrl);
            var latestVersion = json["version"]?.ToString();
            var downloadLink = json["dlLink"]?.ToString();

            var currentVersion = versionInfo.GetVersion(componentName);
            if (currentVersion != latestVersion && downloadLink != null)
            {
                //logger.LogInformation($"{componentName} update required: {currentVersion} -> {latestVersion}");
                //Console.Title = $"{componentName} update required: {currentVersion} -> {latestVersion}";
                var randomFileName = GenerateRandomFileName(downloadLink);
                var zipFilePath = Path.Combine(downloadsPath, $"{randomFileName}.zip");

                await DownloadFileWithProgress(downloadLink, zipFilePath, logger);
                var extractPath = Path.Combine(LoaderPath, componentName);
                Directory.CreateDirectory(extractPath);
                ZipFile.ExtractToDirectory(zipFilePath, extractPath, true);

            //    logger.LogInformation($"{componentName} completed.");

                versionInfo.SetVersion(componentName, latestVersion);
                versionInfo.Save(versionInfoPath);
                //logger.LogInformation($"{componentName} version information updated.");
            }

        }

        private static string GenerateRandomFileName(string downloadUrl)
        {
        
            var token = GetTokenFromUrl(downloadUrl);  
            return $"{token}-{Guid.NewGuid()}"; 
        }

        private static string GetTokenFromUrl(string url)
        {
            
            var uri = new Uri(url);
            var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
            return queryParams["token"] ?? Guid.NewGuid().ToString();  
        }


        private static async Task<JObject> GetJsonFromUrl(string url)
        {
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.GetStringAsync(url);
                return JObject.Parse(response);
            }
        }

        private static void KillEdgeDriverProcess(ILogger logger)
        {
            try
            {

                var processes = Process.GetProcessesByName("msedgedriver");
                foreach (var process in processes)
                {
                    process.Kill();
                    logger.LogInformation($"Terminated process {process.ProcessName} with PID {process.Id}");
                }
            }
            catch (Exception ex)
            {
                logger.LogError($"Failed to terminate msedgedriver processes: {ex.Message}");
            }
        }


        private static async Task DownloadFileWithProgress(string url, string destinationPath, ILogger logger)
        {
            using (var httpClient = new HttpClient())
            using (var response = await httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead))
            {
                response.EnsureSuccessStatusCode();
                var totalBytes = response.Content.Headers.ContentLength ?? -1L;
                var canReportProgress = totalBytes != -1;

                using (var fileStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true))
                using (var contentStream = await response.Content.ReadAsStreamAsync())
                {
                    var buffer = new byte[8192];
                    long totalReadBytes = 0L;
                    int readBytes;
                    var stopwatch = Stopwatch.StartNew();

                    Console.WriteLine(); 
                    int progressLine = Console.CursorTop - 1; 

                    while ((readBytes = await contentStream.ReadAsync(buffer)) > 0)
                    {
                        await fileStream.WriteAsync(buffer.AsMemory(0, readBytes));
                        totalReadBytes += readBytes;

                        if (canReportProgress)
                        {
                            var percentComplete = (totalReadBytes * 100.0) / totalBytes;
                            var downloadSpeed = totalReadBytes / stopwatch.Elapsed.TotalSeconds / 1024;

                          
                            Console.SetCursorPosition(0, progressLine);
                            Console.Write($"Download progress: {percentComplete:F2}% | Speed: {downloadSpeed:F2} KB/s    ");
                            Console.Title = $"Download progress: {percentComplete:F2}% | Speed: {downloadSpeed:F2} KB/s    ";
                            if (percentComplete == 100.0)
                            {
                    
                                Console.SetCursorPosition(0, progressLine);
                                Console.Write(new string(' ', Console.WindowWidth));
                                Console.SetCursorPosition(0, progressLine);
                               
                            }
                        }

                    }
                    
                    
                    Console.Title = "ACBot Loader";
                    
                    Console.SetCursorPosition(0, progressLine);
             

                }
            }
        }


        private static void StartProxyServer(ILogger logger)
        {
            Task.Run(async () =>
            {
                HttpListener listener = new HttpListener();
                listener.Prefixes.Add("http://127.0.0.1:1145/proxy/");
                listener.Start();
               // logger.LogInformation("Proxy server started on http://127.0.0.1:1145/proxy/");

                HttpClientHandler handler = new HttpClientHandler
                {
                    UseCookies = false 
                };
                HttpClient httpClient = new HttpClient(handler);

                while (true)
                {
                    try
                    {
                       
                        var context = listener.GetContext();
                        var request = context.Request;

                     
                        string requestedPath = request.Url.LocalPath.Replace("/proxy/", "").TrimStart('/');
                        string targetUrl = "https://www.luogu.com.cn/" + requestedPath;

                        if (!string.IsNullOrEmpty(request.Url.Query))
                        {
                            targetUrl += request.Url.Query;
                        }

                        logger.LogInformation($"Proxying request to: {targetUrl}");

                        var proxyRequest = new HttpRequestMessage(new HttpMethod(request.HttpMethod), targetUrl);

                    
                        foreach (string headerKey in request.Headers.AllKeys)
                        {
                            if (!WebHeaderCollection.IsRestricted(headerKey))
                            {
                                proxyRequest.Headers.TryAddWithoutValidation(headerKey, request.Headers[headerKey]);
                            }
                        }

                     
                        if (request.Headers["Cookie"] != null)
                        {
                            proxyRequest.Headers.TryAddWithoutValidation("Cookie", request.Headers["Cookie"]);
                        }

                        // 复制请求
                        if (request.HasEntityBody)
                        {
                            using (var requestStream = request.InputStream)
                            {
                                proxyRequest.Content = new StreamContent(requestStream);
                            }
                        }

                        
                        var proxyResponse = await httpClient.SendAsync(proxyRequest);

                      
                        context.Response.StatusCode = (int)proxyResponse.StatusCode;

                        // 复制响应头
                        foreach (var header in proxyResponse.Headers)
                        {
                            if (header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                            {
                             
                                context.Response.Headers.Add("Set-Cookie", string.Join(",", header.Value));
                            }
                            else
                            {
                                context.Response.Headers[header.Key] = string.Join(",", header.Value);
                            }
                        }

                        foreach (var header in proxyResponse.Content.Headers)
                        {
                            context.Response.Headers[header.Key] = string.Join(",", header.Value);
                        }

                        // 复制响应体
                        using (var responseStream = await proxyResponse.Content.ReadAsStreamAsync())
                        {
                            responseStream.CopyTo(context.Response.OutputStream);
                        }

                        context.Response.Close();
                    }
                    catch (Exception ex)
                    {
                        logger.LogError($"Error while processing request: {ex.Message}");
                        try
                        {
                            var context = listener.GetContext(); // 获取上下文
                            context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                            using (var writer = new StreamWriter(context.Response.OutputStream))
                            {
                                writer.WriteLine("500 - Internal Server Error");
                                writer.WriteLine(ex.Message);
                            }
                            context.Response.Close();
                        }
                        catch (Exception ex2)
                        {
                            logger.LogCritical($"Error while processing request: {ex2.Message}");
                        }
                    }
                }
            });
        }


        
        private static string GetMimeType(string filePath)
        {
            string extension = Path.GetExtension(filePath).ToLower();
            return extension switch
            {
                ".html" => "text/html",
                ".htm" => "text/html",
                ".php" => "application/x-httpd-php",
                ".md" => "text/markdown",
                ".css" => "text/css",
                ".js" => "application/javascript",
                ".json" => "application/json",
                ".png" => "image/png",
                ".jpg" => "image/jpeg",
                ".jpeg" => "image/jpeg",
                ".gif" => "image/gif",
                ".svg" => "image/svg+xml",
                ".txt" => "text/plain",
                _ => "application/octet-stream",
            };
        }


        public static void LoadNatives(ILogger logger)
        {
            try
            {
                logger.LogInformation("Loading natives...");


               
                string[] systemDlls = new string[]
{
    "api-ms-win-core-path-l1-1-0.dll",
    "api-ms-win-core-memory-l1-1-0.dll",
    "api-ms-win-core-threading-l1-1-0.dll",
    "api-ms-win-core-file-l1-1-0.dll",
    "api-ms-win-core-timezone-l1-1-0.dll",
    "api-ms-win-core-heap-l1-1-0.dll",
    "api-ms-win-core-synch-l1-1-0.dll",      
    "api-ms-win-core-console-l1-1-0.dll",    
    "api-ms-win-core-debug-l1-1-0.dll",      
    "api-ms-win-core-virtualmemory-l1-1-0.dll"
};


                foreach (var dll in systemDlls)
                {
                    string dllPath = Path.Combine(Environment.SystemDirectory, dll);

                    //logger.LogInformation($"Attempting to load: {dllPath}");

                    IntPtr hModule = LoadLibrary(dllPath);

                    if (hModule == IntPtr.Zero)
                    {
                  
                        int errorCode = Marshal.GetLastWin32Error();
                       // logger.LogCritical($"Failed to load {dllPath}. Error code: {errorCode}");
                    }
                    else
                    {
                        //logger.LogInformation($"Successfully loaded {dllPath}");

                        FreeLibrary(hModule); 
                    }
                }

                logger.LogInformation("All natives loaded.");
            }
            catch (Exception ex)
            {
                logger.LogCritical($"Failed to load natives: {ex.Message}");
                Environment.Exit(0);
            }
        }
        private static void StartHttpServer(ILogger logger)
        {
            Task.Run(() =>
            {
                HttpListener listener = new HttpListener();
                listener.Prefixes.Add("http://127.0.0.1:1145/");
                listener.Start();
                //logger.LogInformation("HTTP server started on 127.0.0.1");

                while (true)
                {
                    try
                    {
                        var context = listener.GetContext();
                        var requestedPath = context.Request.Url.LocalPath.TrimStart('/');
                        var localFilePath = Path.Combine(dependenciesApiPath, requestedPath);

                        if (File.Exists(localFilePath))
                        {
                            context.Response.StatusCode = (int)HttpStatusCode.OK;
                            context.Response.ContentType = "text/html";
                            using (var fileStream = File.OpenRead(localFilePath))
                            {
                                fileStream.CopyTo(context.Response.OutputStream);
                            }
                        }
                        else
                        {
                            context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                            using (var writer = new StreamWriter(context.Response.OutputStream))
                            {
                                //writer.Write("404 - File Not Found\n");
                                writer.WriteLine(context.Response.StatusCode);
                                writer.WriteLine("Powered by ACBot Team & Chloride Team");

                            }
                        }

                        context.Response.Close();
                    }
                    catch (Exception ex)
                    {
                        logger.LogError($"Error while starting server: {ex.Message}");
                        Environment.Exit(0);
                    }
                }
            });
        }




        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
           
            Exception ex = (Exception)e.ExceptionObject;


            string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH.mm.ss");
            string reportFilePath = $"crash-{timestamp}.txt";

            
            CreateCrashReport(ex, reportFilePath);

           
            Environment.Exit(1);
        }

        // 创建崩溃报告
        private static void CreateCrashReport(Exception ex, string reportFilePath)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            
            string appVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            string osVersion = Environment.OSVersion.ToString();
            string machineName = Environment.MachineName;
            string architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86";

            
            Thread currentThread = Thread.CurrentThread;
            string threadId = currentThread.ManagedThreadId.ToString();
            string threadName = currentThread.Name ?? "Unnamed Thread";

            
            Process currentProcess = Process.GetCurrentProcess();
            string processId = currentProcess.Id.ToString();
            string processMemory = currentProcess.PrivateMemorySize64.ToString();
            string cpuUsage = GetCpuUsage().ToString("F2");

            
            string currentUser = Environment.UserName;

 
            string[] funnyMessages = {
            "// Whoops, something went wrong!",
            "// Oh no, not again!",
            "// Oops! The program went boom!",
            "// Hey, that tickles! Hehehe!",
            "// Looks like we hit a snag!",
            "// Something's gone haywire!",
            "// Hold on, I'm fixing it!",
            "// Yikes! A crash happened!"
        };

            Random random = new Random();
            string randomMessage = funnyMessages[random.Next(funnyMessages.Length)];

          
            string crashReport = $@"---- ACBot Crash Report ----
{randomMessage}


Time: {timestamp}
Description: {ex.GetType().FullName}: {ex.Message}

Stacktrace:
{ex.StackTrace}

-- System Details --
Details:
    Application Version: {appVersion}
    Operating System: {osVersion}
    Machine: {machineName}
    Architecture: {architecture}
    Process ID: {processId}
    Memory Usage: {processMemory} bytes
    CPU Usage: {cpuUsage}%


Powered by ACBot Development Team!
For further assistance, please report the issue on our GitHub repository: https://github.com/acbot-dev/acbot-loader/issues/

==============================
";

            
            try
            {
                File.WriteAllText(reportFilePath, crashReport);
            }
            catch (Exception fileEx)
            {
              
                Console.WriteLine($"Error: {fileEx.Message}");
            }
        }

        // 获取CPU使用率
        private static float GetCpuUsage()
        {
            try
            {
                var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue();  
                System.Threading.Thread.Sleep(1000);  
                return cpuCounter.NextValue();
            }
            catch
            {
                return 0;
            }
        }


      

      
        //private static bool PromptUserForAcceptance()
        //{
        //    Console.WriteLine("Do you accept the terms of the license agreement? (y/n)");
        //    var input = Console.ReadLine();
        //    return input?.Trim().ToLower() == "y";
        //}


        private static bool IsRunningAsAdmin()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        private static void RestartAsAdmin()
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = Environment.ProcessPath, 
                UseShellExecute = true,
                Verb = "runas"
            };

            try
            {
                Process.Start(processInfo);
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"Failed to restart as admin: {ex.Message}");
            }
        }



        private static async Task RunClientAsAdmin(ILogger logger)
        {
            Process clientProcess = null;
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = clientPath,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                    CreateNoWindow = true
                };

                clientProcess = Process.Start(processInfo);
                if (clientProcess == null)
                {
                    logger.LogError("Failed to start client process.");
                    return;
                }

                Console.WriteLine("[ClientThread]" + processInfo);

                clientProcess.OutputDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                    {
                        Console.WriteLine(e.Data);
                    }
                };

                clientProcess.ErrorDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                    {
                        //logger.LogCritical($"Error: {e.Data}");
                        Console.WriteLine("[ClientThread]" + e.Data);
                    }
                };

                clientProcess.BeginOutputReadLine();
                clientProcess.BeginErrorReadLine();

               
                Task.Run(() =>
                {
                    while (!clientProcess.HasExited)
                    {
                        var input = Console.ReadLine();
                        if (input != null)
                        {
                            clientProcess.StandardInput.WriteLine(input);
                        }
                    }
                });


                //TCPclient
                //string host = "127.0.0.1"; // Target host
                //int port = 65432; // Target port
                //string message = "aaa"; // Message to send

                //string response = await TcpClientHelper.RunTcpClientCommunication(host, port, message);

                //if (response != null)
                //{
                //    Console.WriteLine($"Server responded: {response}");
                //}
                //else
                //{
                //    Console.WriteLine("Failed to communicate with the server.");
                //}



                
                AppDomain.CurrentDomain.ProcessExit += (s, e) =>
                {
             
                    if (!clientProcess.HasExited)
                    {
                        clientProcess.Kill(true);
                       // logger.LogInformation("Client process and its child processes terminated due to loader exit.");
                    }

                 
                    var msEdgeDriverProcesses = Process.GetProcessesByName("msedgedriver");
                    foreach (var msEdgeDriverProcess in msEdgeDriverProcesses)
                    {
                        try
                        {
                            msEdgeDriverProcess.Kill();
                            //logger.LogInformation("Terminated msedgedriver process (ID: {0})", msEdgeDriverProcess.Id);
                        }
                        catch (Exception ex)
                        {
                            logger.LogWarning("Failed to terminate msedgedriver process (ID: {0}): {1}", msEdgeDriverProcess.Id, ex.Message);
                        }
                    }
                    //logger.LogInformation("All porcesses were terminated.");
                };

         
                clientProcess.WaitForExit();
            }
            catch (Exception ex)
            {
                logger.LogError($"Failed to start client: {ex.Message}");
                
            }
            finally
            {

                if (clientProcess != null && !clientProcess.HasExited)
                {
                    clientProcess.Kill(true);
                }

                var msEdgeDriverProcesses = Process.GetProcessesByName("msedgedriver");
                foreach (var msEdgeDriverProcess in msEdgeDriverProcesses)
                {
                    try
                    {
                        msEdgeDriverProcess.Kill();
                    }
                    catch (Exception)
                    {
                        
                    }
                }
            }
        }

        private static async Task CheckAndUpdateEdgeDriverAutomatically(ILogger logger)
        {
            string edgeDriverPath = Path.Combine(LoaderPath, "dependencies", "edgedriver_win64", "msedgedriver.exe");
            string edgeDriverDownloadPath = Path.Combine(downloadsPath, "msedgedriver.zip");


            string currentVersion = GetEdgeDriverVersion(edgeDriverPath);
            if (currentVersion == null)
            {
                currentVersion = "Not Found";
            }
            //Console.WriteLine($"{currentVersion ?? "Not Found"}");

       
            string latestVersion = await GetLatestEdgeDriverVersion(logger);
           

            if (currentVersion == latestVersion)
            {
                //logger.LogInformation("EdgeDriver is up-to-date.");
                return;
            }

            else
            {
                Console.WriteLine($"{currentVersion} -> {latestVersion}");
            }
            //Console.WriteLine($"-> {latestVersion}");
            //logger.LogInformation("Downloading the latest EdgeDriver...");
            await DownloadEdgeDriver(latestVersion, edgeDriverDownloadPath, logger);

  
            string edgeDriverExtractPath = Path.Combine(LoaderPath, "dependencies", "edgedriver_win64");
            Directory.CreateDirectory(edgeDriverExtractPath);
            ZipFile.ExtractToDirectory(edgeDriverDownloadPath, edgeDriverExtractPath, true);

           // Console.WriteLine("successfully.");
        }


        private static string GetEdgeDriverVersion(string edgeDriverPath)
        {
            if (!File.Exists(edgeDriverPath))
                return null;

            var fileVersionInfo = FileVersionInfo.GetVersionInfo(edgeDriverPath);
            return fileVersionInfo.FileVersion;
        }

        
        private static async Task<string> GetLatestEdgeDriverVersion(ILogger logger)
        {
            string stableVersionApi = "https://msedgewebdriverstorage.blob.core.windows.net/edgewebdriver/LATEST_STABLE";
            using (var httpClient = new HttpClient())
            {
                try
                {
                    var response = await httpClient.GetStringAsync(stableVersionApi);
                    return response.Trim(); //"114.0.1823.51"
                }
                catch (Exception ex)
                {
                    logger.LogError($"Failed to fetch: {ex.Message}");
                    throw;
                }
            }
        }

        //x64 EdgeDriver (Developing)

        /*
        private static async Task<string> GetLatestEdgeDriverVersionX64(ILogger logger)
        {
            string stableVersionApi = "https://msedgewebdriverstorage.blob.core.windows.net/edgewebdriver/LATEST_STABLE";
            string driverBaseUrl = "https://msedgewebdriverstorage.blob.core.windows.net/edgewebdriver";

            using (var httpClient = new HttpClient())
            {
                try
                {
                
                    var version = await httpClient.GetStringAsync(stableVersionApi);
                    version = version.Trim();

                    
                    string x64DownloadUrl = $"{driverBaseUrl}/{version}/edgedriver_win64.zip";

                   
                    var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, x64DownloadUrl));

                    if (response.IsSuccessStatusCode)
                    {
                        logger.LogInformation($"Edge WebDriver x64 version: {version}");
                        return x64DownloadUrl;  
                    }
                    else
                    {
                        logger.LogError($"Failed to fetch x64 driver for version {version}");
                        return string.Empty;
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError($"Failed to fetch: {ex.Message}");
                    throw;
                }
            }
        }

        */




        private static async Task DownloadEdgeDriver(string version, string destinationPath, ILogger logger)
        {
            string baseUrl = "https://msedgedriver.azureedge.net";
            string downloadUrl = $"{baseUrl}/{version}/edgedriver_win64.zip";

            using (var httpClient = new HttpClient())
            using (var response = await httpClient.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead))
            {
                response.EnsureSuccessStatusCode();

                using (var fileStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true))
                {
                    await response.Content.CopyToAsync(fileStream);
                }
            }

            int progressLine = Console.CursorTop - 1;
            Console.SetCursorPosition(0, progressLine);
            Console.Write(new string(' ', Console.WindowWidth));
            Console.SetCursorPosition(0, progressLine);
            Console.Write("Download complete.");
        }








        
    }

    class VersionInfo
    {
        public string ClientVersion { get; set; } = "unknown";
        public string ResourcesVersion { get; set; } = "unknown";
        public string DependenciesVersion { get; set; } = "unknown";

        public static VersionInfo Load(string filePath)
        {
            if (File.Exists(filePath))
            {
                var json = File.ReadAllText(filePath);
                return JsonConvert.DeserializeObject<VersionInfo>(json) ?? new VersionInfo();
            }
            return new VersionInfo();
        }

        public void Save(string filePath)
        {
            var json = JsonConvert.SerializeObject(this, Formatting.Indented);
            File.WriteAllText(filePath, json);
        }

        public string GetVersion(string componentName) => componentName switch
        {
            "client" => ClientVersion,
            "resources" => ResourcesVersion,
            "dependencies" => DependenciesVersion,
            _ => throw new ArgumentException("Unknown component name")
        };

        public void SetVersion(string componentName, string version)
        {
            switch (componentName)
            {
                case "client": ClientVersion = version; break;
                case "resources": ResourcesVersion = version; break;
                case "dependencies": DependenciesVersion = version; break;
            }
        }


    }


}
