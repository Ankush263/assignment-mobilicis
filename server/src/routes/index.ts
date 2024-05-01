import { Router } from 'express';
import { router as userRouter } from './user.router';

export const router = Router();

router.use('/user', userRouter);
