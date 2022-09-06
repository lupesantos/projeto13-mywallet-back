import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient, ServerApiVersion } from 'mongodb';
import Joi from 'joi';
import dayjs from 'dayjs';
import bcrypt from 'bcrypt';

dotenv.config();

const server = express();

server.use(cors());
server.use(express.json());

//conexao com mongodb

const mongoClient = new MongoClient(process.env.MONGO_URI);

let db;

mongoClient.connect().then(() => {
	db = mongoClient.db('mywallet');
});

const usuarioSchema = Joi.object({
	name: Joi.string().required(),
	email: Joi.string().email().required(),
	password: Joi.string().min(6).max(10).required(),
	confirm: Joi.any().valid(Joi.ref('password')).required(),
});

server.post('/cadastro', async (req, res) => {
	const user = req.body;
	const passwordHash = bcrypt.hashSync(user.password, 10);

	console.log(user.password);
	console.log(passwordHash);

	const validation = usuarioSchema.validate(user, { abortEarly: false });

	if (validation.error) {
		const errors = validation.error.details.map((value) => value.message);
		return res.status(422).send(errors);
	}

	try {
		const existe = await db
			.collection('usuarios')
			.findOne({ email: user.email });

		if (!existe) {
			await db.collection('usuarios').insertOne({
				name: user.name,
				email: user.email,
				password: passwordHash,
			});
		} else {
			return res.status(400).send('Usuário já cadastrado!');
		}
	} catch (error) {
		res.status(500).send(error.message);
	}

	res.send(user);
});

server.post('/login', async (req, res) => {
	const { email, password } = req.body;

	try {
		const existe = await db.collection('usuarios').findOne({ email: email });

		if (existe && bcrypt.compareSync(password, existe.password)) {
			res.status(200).send('LOGOU!');
		} else {
			res.status(401).send('Usuário ou senha inválido');
		}
	} catch (error) {
		res.status(500).send(error.message);
	}
});
// schemas (JOI)

// rotas usuario

// rotas de entrada e saida

server.listen(5000, () => console.log('Server running in port 5000'));
