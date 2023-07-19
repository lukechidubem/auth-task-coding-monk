import mongoose, { Document, model, Schema } from 'mongoose';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import validator from 'validator';

export interface IUser extends Document {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  verified: boolean;
  otp: string;
  otpExpiresTime: Date;
  passwordChangedAt?: Date | number;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  active: boolean;
  correctPassword: (
    candidatePassword: string,
    userPassword: string
  ) => Promise<boolean>;
  correctOTP: (candidateOTP: string, userOTP: string) => Promise<boolean>;
  changedPasswordAfter: (JWTTimestamp: number) => boolean;
  createPasswordResetToken: () => string;
}

const userSchema: Schema<IUser> = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'Please tell us your first name!'],
  },

  lastName: {
    type: String,
    required: [true, 'Please tell us your last name!'],
  },

  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
  },

  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false,
  },

  verified: {
    type: Boolean,
    default: false,
  },

  otp: {
    type: String,
  },

  otpExpiresTime: {
    type: Date,
  },

  passwordChangedAt: Date,

  passwordResetToken: String,

  passwordResetExpires: Date,

  active: {
    type: Boolean,
    default: true,
    select: false,
  },
});

userSchema.pre<IUser>('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  next();
});

// Hashing OTP on modified
userSchema.pre<IUser>('save', async function (next) {
  // Only run this function if OTP was actually modified
  if (!this.isModified('otp') || !this.otp) return next();

  // Hash the password with cost of 12
  this.otp = await bcrypt.hash(this.otp.toString(), 12);

  next();
});

userSchema.pre<IUser>('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;

  next();
});

userSchema.pre(/^find/, function (next) {
  // this points to the current query
  this.find({ active: { $ne: false } });
  next();
});

userSchema.methods.correctPassword = async function (
  candidatePassword: string,
  userPassword: string
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Comparing User OTP with the Database OTP
userSchema.methods.correctOTP = async function (
  candidateOTP: string,
  userOTP: string
): Promise<boolean> {
  return await bcrypt.compare(candidateOTP, userOTP);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp: number) {
  if (this.passwordChangedAt) {
    const changedTimestamp = Math.floor(
      this.passwordChangedAt.getTime() / 1000
    );

    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

export const User = model<IUser>('User', userSchema);
