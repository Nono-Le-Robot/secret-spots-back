// server.js
const express = require('express');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const corsOptions = {
    origin: 'http://localhost:3000', // Remplacez ceci par l'URL de votre frontend
    methods: 'GET,POST,PUT,DELETE', // Les méthodes autorisées
    credentials: true, // Permet l'envoi de cookies avec la requête
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json()); // Pour analyser les requêtes JSON
app.use(cookieParser());
// Connexion à MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connexion à MongoDB réussie'))
    .catch(err => console.log('Erreur de connexion à MongoDB :', err));

// Routes d'authentification
app.use('/api', authRoutes);



app.listen(port, () => {
    console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
