import { Router } from 'express';
import {
	signup,
	login,
	getUser,
	protect,
	resetPassword,
} from '../controllers/user.controllers';

export const router = Router();

router.route('/signup').post(signup);
router.route('/login').post(login);
router.route('/resetPassword').patch(protect, resetPassword);
router.route('/').get(protect, getUser);
