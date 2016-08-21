using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace FocusStealer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        [DllImport("user32.dll")]
        static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool FlashWindow(IntPtr hwnd, bool bInvert);

        public MainWindow()
        {
            InitializeComponent();

            var dispatcherTimer = new DispatcherTimer();
            dispatcherTimer.Tick += delegate
            {
                if (cbStealingActive.IsChecked == true)
                    Focus();
            };
            dispatcherTimer.Interval = TimeSpan.FromSeconds(5);
            dispatcherTimer.Start();

            var doNotWait = StartTcpServerAsync();
        }

        private void Focus()
        {
            if (Debugger.IsAttached)
                Debugger.Break();
            else
                SetForegroundWindow(new WindowInteropHelper(this).Handle);
        }

        private async Task StartTcpServerAsync()
        {
            var tcpListener = new TcpListener(new IPEndPoint(IPAddress.Loopback, 10000));
            tcpListener.Start();
            while (true)
            {
                var client = await tcpListener.AcceptTcpClientAsync();
                client.Close();
                Focus();
            }
        }
    }
}
