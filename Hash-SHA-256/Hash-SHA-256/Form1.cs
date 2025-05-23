using System;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace Hash_SHA_256
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            textBox1.MaxLength = 1000000000;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string input = textBox1.Text;

            // Tính toán SHA-256
            string hash = SHA256.ComputeSHA256(input);

            byte[] hashbyte = SHA256.ComputeSHA256Bytes(input);

            // Hiển thị kết quả
            //textBox2.Text = hash;
            textBox2.Text = string.Join(", ", hashbyte);
        }
    }
}
