require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();


//config json response
app.use(express.json());

//models
const User = require('./models/User');

// public route
app.get('/', (req, res) => {
  res.status(200).json({ msg: 'Teste de API' });
});



//private route
app.get('/user/:id', checkToken, async (req, res) => {
  const id = req.params.id;
  // check exists
  const user = await User.findById(id, '-password');
  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado.' });
  };
  res.status(200).json({ user });
});

// check token
function checkToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ msg: 'Acesso negado.' });
  };
  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ msg: 'Token inváido' });
  }
};


// User registration
app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;
  // validations
  if (!name) {
    return res.status(422).json({ msg: 'Nome é obrigatório!' });
  };
  if (!email) {
    return res.status(422).json({ msg: 'E-mail é obrigatório!' });
  };
  if (!password) {
    return res.status(422).json({ msg: 'Senha é obrigatória!' });
  };
  if (confirmpassword !== password) {
    return res.status(422).json({ msg: 'Senhas não conferem!' });
  };

  //check exists
  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res.status(422).json({ msg: 'E-mail já cadastrado! Utilize outro e-mail.' });
  };

  //create password
  const salt = await bcrypt.genSalt(14);
  const passHash = await bcrypt.hash(password, salt);

  // create  user
  const user = new User({
    name,
    email,
    password: passHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: 'Usuário criado com sucesso.' })
  } catch (error) {
    console.log(error)
    res.status(500).json({ msg: 'Deu ruim. Tente mais tarde.' });
  };
});

// login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  //validations
  if (!email) {
    return res.status(422).json({ msg: 'E-mail é obrigatório!' });
  };
  if (!password) {
    return res.status(422).json({ msg: 'Senha é obrigatória!' });
  };

  // check exists
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ msg: 'Usuário não cadastrado.' });
  };

  // check password match
  const checkPass = await bcrypt.compare(password, user.password);
  if (!checkPass) {
    return res.status(422).json({ msg: 'Senha inválida!' });
  };

  try {
    const secret = process.env.SECRET;
    const token = jwt.sign({
      id: user._id
    }, secret);

    return res.status(200).json({ msg: 'Tudo certo!', token });

  } catch (error) {
    console.log(error)
    res.status(500).json({ msg: 'Deu ruim. Tente mais tarde.' });
  }
});


// credential to db connection
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose.set('strictQuery', true); //desligar o warning do mongoose

// db conn
mongoose
  .connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.wgv46hm.mongodb.net/?retryWrites=true&w=majority`)
  .then(() => {
    app.listen(3000);
    console.log("Servidor ativo e DB conectado")
  })
  .catch((err) => console.log(err));



