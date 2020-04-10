using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;
using System.Numerics;

namespace SimpleRSA
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        RSA rsa = new RSA();
        public MainWindow()
        {
            InitializeComponent();

            rsa.KeyGenerated += Rsa_KeyGenerated;
            rsa.MessageEncrypted += Rsa_MessageEncrypted;
        }

        private void Rsa_MessageEncrypted(object sender, EventArgs e)
        {
            messageEncryptedInfoBlock.Text = "yes";
            messageEncryptedInfoBlock.Foreground = Brushes.Green;
            decryptButton.Visibility = Visibility.Visible;
        }

        private void Rsa_KeyGenerated(object sender, EventArgs e)
        {
            keyGeneratedInfoBlock.Text = "yes";
            keyGeneratedInfoBlock.Foreground = Brushes.Green;
            loadButton.Visibility = Visibility.Visible;
        }

        string inputText;

        private void loadButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.InitialDirectory = AppDomain.CurrentDomain.BaseDirectory;
            dialog.Filter = "text files (*.txt)|*.txt";

            if (dialog.ShowDialog() == true) //nullable bool
            {
                using (StreamReader reader = File.OpenText(dialog.FileName))
                {
                    inputText = reader.ReadToEnd();
                    mainTextBlock.Text += "Message: " + inputText + Environment.NewLine;

                    encryptButton.Visibility = Visibility.Visible;
                }
            }
        }

        private void encryptButton_Click(object sender, RoutedEventArgs e)
        {
            rsa.Encrypt(inputText);

            SaveFileDialog dialog = new SaveFileDialog();
            dialog.InitialDirectory = AppDomain.CurrentDomain.BaseDirectory;
            dialog.Filter = "text files (*.txt)|*.txt";
            dialog.FileName = "ciphertext";

            if (dialog.ShowDialog() == true)
            {
                using (StreamWriter writer = new StreamWriter(dialog.FileName))
                {
                    writer.WriteLine(rsa.Ciphertext.ToString("x"));
                }
            }

        }

        private void decryptButton_Click(object sender, RoutedEventArgs e)
        {
            rsa.Decrypt(rsa.Ciphertext);

            SaveFileDialog dialog = new SaveFileDialog();
            dialog.InitialDirectory = AppDomain.CurrentDomain.BaseDirectory;
            dialog.Filter = "text files (*.txt)|*.txt";
            dialog.FileName = "output";

            if (dialog.ShowDialog() == true)
            {
                using (StreamWriter writer = new StreamWriter(dialog.FileName))
                {
                    writer.WriteLine(rsa.DecryptedCiphertext);
                }
            }
        }

        private void generateKeyButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("The key is being generated. This may take up to 20 seconds. " +
                "Please wait patienlty. When the key will be generated " +
                "you will see green yes near the 'Key generated' " +
                "text", "Please wait patiently", MessageBoxButton.OK);
            rsa.GenerateKey();
        }
    }
}
