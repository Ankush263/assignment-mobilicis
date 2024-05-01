import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

export const connection = async () => {
	try {
		const connectionInstance = await mongoose.connect(
			`${process.env.MONGO_URI}`
		);
		console.log(
			`\nMongoDB is connected to DB HOST: ${connectionInstance.connection.host}`
		);
	} catch (error) {
		throw new Error(error);
	}
};
