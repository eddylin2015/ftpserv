using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Text;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading.Tasks;

namespace SharpFtpServer
{
    class Program
    {

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);

        [DllImport("user32.dll")]
        static extern IntPtr GetShellWindow();

        [DllImport("user32.dll")]
        static extern IntPtr GetDesktopWindow();

        static NotifyIcon notifyIcon;
        static IntPtr processHandle;
        static IntPtr WinShell;
        static IntPtr WinDesktop;
        static MenuItem HideMenu;
        static MenuItem RestoreMenu;

        static void Main(string[] args)
        {
            notifyIcon = new NotifyIcon();
            notifyIcon.Icon = new Icon("icon1.ico");
            notifyIcon.Text = "Monitor";
            notifyIcon.Visible = true;

            ContextMenu menu = new ContextMenu();
            HideMenu = new MenuItem("Hide", new EventHandler(Minimize_Click));
            RestoreMenu = new MenuItem("Restore", new EventHandler(Maximize_Click));

            menu.MenuItems.Add(RestoreMenu);
            menu.MenuItems.Add(HideMenu);
            menu.MenuItems.Add(new MenuItem("Exit", new EventHandler(CleanExit)));

            notifyIcon.ContextMenu = menu;

            //You need to spin off your actual work in a different thread so that the Notify Icon works correctly
            //Task.Factory.StartNew(Run);

            processHandle = Process.GetCurrentProcess().MainWindowHandle;

            WinShell = GetShellWindow();

            WinDesktop = GetDesktopWindow();

            //Hide the Window
            ResizeWindow(false);
            //Console.OutputEncoding = Encoding.UTF8;
#if DEBUG
            foreach (EncodingInfo einfo in Encoding.GetEncodings())
                Console.WriteLine("{0}{1}{2}{3}",einfo.CodePage, einfo.DisplayName, einfo.Name, einfo.ToString());
#endif
            ///////////////////////////////////////////////////
            //IPAddress ip = IPAddress.Parse("192.168.102.135");
            //using (FtpServer server = new FtpServer(IPAddress.IPv6Any, 21))
            using (FtpServer server = new FtpServer())
            {
                server.Start();

                Console.WriteLine("Press any key to stop...");
                Application.Run();
                while (!Console.ReadLine().Equals("Q")) { }
            }
        }
        static void Run()
        {
            Console.WriteLine("Listening to messages");

            while (true)
            {
                System.Threading.Thread.Sleep(1000);
            }
        }


        private static void CleanExit(object sender, EventArgs e)
        {
            notifyIcon.Visible = false;
            Application.Exit();
            Environment.Exit(1);
        }


        static void Minimize_Click(object sender, EventArgs e)
        {
            ResizeWindow(false);
        }


        static void Maximize_Click(object sender, EventArgs e)
        {
            ResizeWindow();
        }

        static void ResizeWindow(bool Restore = true)
        {
            if (Restore)
            {
                RestoreMenu.Enabled = false;
                HideMenu.Enabled = true;
                SetParent(processHandle, WinDesktop);
            }
            else
            {
                RestoreMenu.Enabled = true;
                HideMenu.Enabled = false;
                SetParent(processHandle, WinShell);
            }
        }
    }
}
