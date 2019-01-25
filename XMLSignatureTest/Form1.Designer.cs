namespace XMLSignatureTest
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.button1 = new System.Windows.Forms.Button();
            this.lblDocSig = new System.Windows.Forms.Label();
            this.lblAssertionSignature = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // textBox1
            // 
            this.textBox1.Location = new System.Drawing.Point(148, 23);
            this.textBox1.Multiline = true;
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new System.Drawing.Size(640, 227);
            this.textBox1.TabIndex = 0;
            this.textBox1.Text = resources.GetString("textBox1.Text");
            this.textBox1.TextChanged += new System.EventHandler(this.textBox1_TextChanged);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(22, 23);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(120, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "Base64 Saml Response";
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(719, 301);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(69, 24);
            this.button1.TabIndex = 2;
            this.button1.Text = "Check Signing";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // lblDocSig
            // 
            this.lblDocSig.AutoSize = true;
            this.lblDocSig.Location = new System.Drawing.Point(296, 284);
            this.lblDocSig.Name = "lblDocSig";
            this.lblDocSig.Size = new System.Drawing.Size(107, 13);
            this.lblDocSig.TabIndex = 3;
            this.lblDocSig.Text = "Document Signature:";
            // 
            // lblAssertionSignature
            // 
            this.lblAssertionSignature.AutoSize = true;
            this.lblAssertionSignature.Location = new System.Drawing.Point(305, 324);
            this.lblAssertionSignature.Name = "lblAssertionSignature";
            this.lblAssertionSignature.Size = new System.Drawing.Size(101, 13);
            this.lblAssertionSignature.TabIndex = 4;
            this.lblAssertionSignature.Text = "Assurtion Signature:";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 475);
            this.Controls.Add(this.lblAssertionSignature);
            this.Controls.Add(this.lblDocSig);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.textBox1);
            this.Name = "Form1";
            this.Text = "Saml Response Signature Test";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Label lblDocSig;
        private System.Windows.Forms.Label lblAssertionSignature;
    }
}

