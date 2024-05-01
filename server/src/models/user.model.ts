import mongoose, { Model } from 'mongoose';
import validator from 'validator';
import bcrypt from 'bcryptjs';

export interface UserInterface {
	_id?: string;
	firstName: string;
	lastName: string;
	email: string;
	password: string;
	image: string;
	os: string;
	role: string;
}

const userSchema = new mongoose.Schema<UserInterface>(
	{
		firstName: {
			type: String,
		},
		lastName: {
			type: String,
		},
		email: {
			type: String,
			required: [true, 'User must have an email'],
			unique: true,
			lowercase: true,
			validate: [validator.isEmail, 'please provide a valid email'],
		},
		password: {
			type: String,
			required: [true, 'please provide a password'],
		},
		image: {
			type: String,
		},
		os: {
			type: String,
		},
		role: {
			type: String,
			enum: ['Admin', 'User'],
			default: 'User',
		},
	},
	{
		timestamps: true,
	}
);

userSchema.methods.correctPassword = async function (
	candidatePassword: string,
	userPassword: string
) {
	return await bcrypt.compare(candidatePassword, userPassword);
};

export const User: Model<any> = mongoose.model('User', userSchema);
