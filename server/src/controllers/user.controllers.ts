import { User } from '../models/user.model';
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { catchAsync } from '../utils/catchAsync';
import { AppError } from '../utils/appError';
import bcrypt from 'bcryptjs';
import { UserInterface } from '../models/user.model';
import { UAParser } from 'ua-parser-js';
dotenv.config();

const signToken = (id: string) => {
	return jwt.sign({ id }, process.env.JWT_SECRET, {
		expiresIn: process.env.JWT_EXPIRES_IN,
	});
};

const createAndSendToken = (
	user: UserInterface,
	statusCode: number,
	res: Response
) => {
	const token = signToken(user._id);

	const cookieOptions: {
		expires: Date;
		httpOnly: boolean;
		secure?: boolean;
	} = {
		expires: new Date(
			Date.now() +
				parseInt(process.env.JWT_COOKIE_EXPIRES_IN) * 24 * 60 * 60 * 1000
		),
		httpOnly: true,
	};

	if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

	res.cookie('jwt', token, cookieOptions);

	res.json({ token });
};

export const login = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		const {
			email,
			password,
			os,
		}: { email: string; password: string; os: string } = req.body;

		if (!email || !password) {
			return next(new AppError(`Please provide email and password`, 404));
		}

		const user = await User.findOne({ email }).select('+password');

		if (!user || !bcrypt.compareSync(password, user.password)) {
			return next(new AppError(`Incorrect email or password`, 401));
		}

		createAndSendToken(user, 200, res);
	}
);

export const signup = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		const {
			firstName,
			lastName,
			email,
			password,
			role,
		}: {
			firstName: string;
			lastName: String;
			email: string;
			password: string;
			role: string;
		} = req.body;

		const existUser: UserInterface[] = await User.find({ email });

		if (existUser.length > 0) {
			return next(new AppError(`user with this email is already exists`, 404));
		}

		if (!email || !password) {
			return next(new AppError(`Please provide email and password`, 400));
		}

		const ua = req.get('User-Agent');

		const parser = new UAParser(ua);
		console.log(parser.getResult(), ua);

		const hashedPassword: string = bcrypt.hashSync(password, 12);

		const newUser: UserInterface = await User.create({
			firstName,
			lastName,
			email,
			password: hashedPassword,
			role,
		});

		createAndSendToken(newUser, 202, res);
	}
);

export const protect = catchAsync(
	async (req: Request | any, res: Response, next: NextFunction) => {
		let token: string;

		if (
			req.headers.authorization &&
			req.headers.authorization.startsWith('Bearer')
		) {
			token = req.headers.authorization.split(' ')[1];
		} else if (req.cookies.jwt) {
			token = req.cookies.jwt;
		}
		if (!token) {
			return next(
				new AppError(`You aren't logged in! Please log in to get access`, 401)
			);
		}

		const decoded: any = jwt.decode(token);

		let freshUser: UserInterface;

		freshUser = await User.findById(decoded.id);

		if (!freshUser) {
			return next(
				new AppError(
					`The user belonging to this token does no longer exist`,
					401
				)
			);
		}

		req.user = freshUser;

		next();
	}
);

export const restrictTo = (...roles: string[]) => {
	return (req: Request | any, res: Response, next: NextFunction) => {
		if (!roles.includes(req.user.role)) {
			return next(
				new AppError(`You don't have permission to perform this action`, 403)
			);
		}
		next();
	};
};

export const resetPassword = catchAsync(
	async (req: Request | any, res: Response, next: NextFunction) => {
		const user = await User.findById(req.user.id);

		if (
			!(await user.correctPassword(req.body.currentPassword, user.password))
		) {
			return next(new AppError(`Your current password is wrong`, 401));
		}

		user.password = await bcrypt.hash(req.body.password, 12);
		await user.save();

		createAndSendToken(user, 200, res);
	}
);

export const getUser = catchAsync(
	async (req: Request | any, res: Response, next: NextFunction) => {
		const user = await User.findById(req.user.id);

		res.status(200).json({
			status: 'success',
			data: user,
		});
	}
);

export const getAllUsers = catchAsync(
	async (req: Request | any, res: Response, next: NextFunction) => {
		const user = await User.find();

		res.status(200).json({
			status: 'success',
			data: user,
		});
	}
);
