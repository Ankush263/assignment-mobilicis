import { Router } from 'express';
import {
	signup,
	login,
	getUser,
	protect,
	resetPassword,
	restrictTo,
} from '../controllers/user.controllers';

export const router = Router();

router.route('/signup').post(signup);
router.route('/login').post(login);
router.route('/resetPassword').patch(protect, resetPassword);
router.route('/me').get(protect, getUser);
router.route('/').get(protect, restrictTo('Admin'), getUser);
