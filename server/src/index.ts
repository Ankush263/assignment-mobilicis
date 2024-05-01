import { connection } from './db/index';
import app from './app';
import http from 'http';
import dotenv from 'dotenv';

dotenv.config();

const server = http.createServer(app);

process.env.TZ = 'Asia/Calcutta';

connection()
	.then(() => {
		server.listen(process.env.PORT || 8000, () => {
			console.log(`Server is running at port: ${process.env.PORT}`);
		});
	})
	.catch((error) => {
		throw new Error(error);
	});
