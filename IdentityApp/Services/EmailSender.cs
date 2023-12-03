using Microsoft.AspNetCore.Identity.UI.Services;
using System.Net;
using System.Net.Mail;

namespace IdentityApp.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _config;
        public EmailSender(IConfiguration config)
        {
            _config = config;
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            string fromMail = _config.GetValue<string>("EmailService:FromEmailAddress");
            string fromPassword = _config.GetValue<string>("EmailService:FromEmailPassword"); // bukan password email

            MailMessage message = new MailMessage();
            message.From = new MailAddress(fromMail);
            message.Subject = subject;
            message.To.Add(new MailAddress(email));
            message.Body = htmlMessage;
            message.IsBodyHtml = true;


            var smtpClient = new SmtpClient(_config.GetValue<string>("EmailService:EmailHost"))
            {
                Port = _config.GetValue<int>("EmailService:EmailPort"),
                // UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromMail, fromPassword),
                EnableSsl = true,
            };

            return smtpClient.SendMailAsync(message);
        }
    }
}
