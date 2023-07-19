import dotenv from 'dotenv';
import sgMail from '@sendgrid/mail';

dotenv.config();

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || '';

sgMail.setApiKey(SENDGRID_API_KEY);

interface EmailOptions {
  to: string;
  sender?: string;
  subject: string;
  text?: string;
  html: string;
  attachments?: any[];
}

const sendSGMail = async ({
  to,
  sender,
  subject,
  text,
  html,
  attachments,
}: EmailOptions): Promise<void> => {
  try {
    const from = sender || 'lukechidubem@gmail.com';

    const msg = {
      to: to,
      from,
      subject,
      html,
      attachments,
    };

    await sgMail.send(msg);
    console.log('Email sent successfully');
  } catch (error) {
    console.error(error);
  }
};

export const sendMail = async (args: EmailOptions): Promise<void> => {
  return sendSGMail(args);
};

export const sendMail2 = async (args: EmailOptions): Promise<void> => {
  if (process.env.NODE_ENV !== 'development') {
    return Promise.resolve();
  } else {
    return sendSGMail(args);
  }
};
