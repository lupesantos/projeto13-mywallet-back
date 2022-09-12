import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient, ServerApiVersion } from 'mongodb';
import Joi from 'joi';
import dayjs from 'dayjs';
import bcrypt from 'bcrypt';
import { v4 as uuid } from 'uuid';

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

const innOutSchema = Joi.object({
	valor: Joi.number().required(),
	descricao: Joi.string().max(20),
});

server.post('/cadastro', async (req, res) => {
	const user = req.body;
	const passwordHash = bcrypt.hashSync(user.password, 10);
	const validation = usuarioSchema.validate(user, { abortEarly: false });

	if (validation.error) {
		const errors = validation.error.details
			.map((value) => value.message)
			.join(',')
			.replace('[ref:password]', 'equal to password');
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
			const token = uuid();
			await db.collection('sessions').insertOne({
				userId: existe._id,
				token: token,
			});

			res.status(200).send({ token: token, name: existe.name });
		} else {
			res.status(401).send('Usuário ou senha inválido');
		}
	} catch (error) {
		res.status(500).send(error.message);
	}
});
// schemas (JOI)

server.post('/nova-entrada', async (req, res) => {
	const entrada = req.body;

	const validation = innOutSchema.validate(entrada, { abortEarly: false });

	if (validation.error) {
		const errors = validation.error.details.map((value) => value.message);
		return res.status(422).send(errors);
	}

	try {
		const token = req.headers.authorization?.replace('Bearer ', '');
		let now = dayjs();

		const user = await db.collection('sessions').findOne({ token: token });
		if (!user) {
			res.sendStatus(401);
		} else {
			await db.collection('carteira').insertOne({
				userId: user.userId,
				type: 'entrada',
				valor: entrada.valor,
				descricao: entrada.descricao,
				dia: now.format('DD/MM'),
			});
			res.status(201).send(entrada);
		}
	} catch (error) {
		console.log(error);
	}
});

server.post('/nova-saida', async (req, res) => {
	const saida = req.body;

	const validation = innOutSchema.validate(saida, { abortEarly: false });

	if (validation.error) {
		const errors = validation.error.details.map((value) => value.message);
		return res.status(422).send(errors);
	}

	try {
		const token = req.headers.authorization?.replace('Bearer ', '');

		let now = dayjs();

		const user = await db.collection('sessions').findOne({ token: token });

		if (!user) {
			res.sendStatus(401);
		} else {
			await db.collection('carteira').insertOne({
				userId: user.userId,
				type: 'saida',
				valor: saida.valor,
				descricao: saida.descricao,
				dia: now.format('DD/MM'),
			});
			res.status(201).send(saida);
		}
	} catch (error) {
		console.log(error);
	}
});

server.get('/extrato', async (req, res) => {
	const token = req.headers.authorization?.replace('Bearer ', '');

	try {
		const user = await db.collection('sessions').findOne({ token: token });

		if (!user) {
			res.sendStatus(401);
		} else {
			const extrato = await db
				.collection('carteira')
				.find({ userId: user.userId })
				.toArray();

			res.send(extrato);
		}
	} catch (error) {
		console.log(error);
	}
});

server.put('/delete', async (req, res) => {
	const token = req.headers.authorization?.replace('Bearer ', '');
	const user = await db.collection('sessions').find().toArray();

	let usuario = user.filter((value) => value.token === token);

	const { _id: id } = usuario;

	try {
		await db.collection('sessions').deleteOne({ _id: id });
		res.send('ok');
	} catch (error) {
		console.log(error);
		res.sendStatus(500);
	}
});

server.listen(5000, () => console.log('Server running in port 5000'));
