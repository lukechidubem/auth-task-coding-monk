import express from 'express';
import authController from '../controllers/authController';

const router = express.Router();

router.post('/signup', authController.signup, authController.sendOTP);
router.post('/sendOTP', authController.sendOTP);
router.post('/verify-email', authController.verifyEmail);
router.post('/login', authController.login);
router.post('/forgot-password', authController.forgotPassword);
router.patch('/reset-password/:token', authController.resetPassword);

export default router;
