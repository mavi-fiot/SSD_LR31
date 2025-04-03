const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';
const OAUTH_URL = "https://dev-5i8s1bbpdxtdh2ez.us.auth0.com";
const CLIENT_ID = "Hbtw5TLwM0iWe1wYxFlf9TqN3hCfc3mH";
const CLIENT_SECRET = "-Ml-EIe7qZmNr8VEIT27fvZd_n-7eJl1nen4y0gsg8TiBm9Iy85P7qCv7zmtR9S_";
const REDIRECT_URI = "http://localhost:3000/api/authorize";
const port = 3000;

console.log("Завантаження публічного ключа...");
const PUBLIC_KEY_PATH = path.join(__dirname, 'dev-5i8s1bbpdxtdh2ez.pem');
let publicKey;

try {
    publicKey = fs.readFileSync(PUBLIC_KEY_PATH, { encoding: 'utf8' });
    console.log("Публічний ключ успішно завантажено.");
} catch (error) {
    console.error('Помилка при зчитуванні публічного ключа:', error.message);
    process.exit(1);
}

const verifyToken = (token) => {
    if (!publicKey) {
        console.error('Публічний ключ не завантажено');
        return false;
    }
    try {
        console.log("Перевірка токена:", token);
        const decoded = jwt.verify(token, publicKey, {
            algorithms: ['RS256'],
            issuer: `${OAUTH_URL}/`,
            audience: [`${OAUTH_URL}/api/v2/`, `${OAUTH_URL}/userinfo`]
        });
        console.log("Токен успішно перевірено:", decoded);
        return true;
    } catch (err) {
        console.error('Токен недійсний:', err.message);
        return false;
    }
};

app.get('/', async (req, res) => {
    console.log("Вхідний запит на '/'");
    console.log("Заголовки запиту:", req.headers);

    const token = req.get(SESSION_KEY);
    console.log("Отримано токен:", token);

    if (token) {
        console.log("Знайдено заголовок авторизації:", token);

        if (!verifyToken(token)) {
            console.error("Перевірка токена не вдалася.");
            return res.status(401).json({ error: 'Недійсний токен авторизації' });
        }

        try {
            console.log("Отримання інформації про користувача...");
            const user_data = await axios.get(`${OAUTH_URL}/userinfo`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            console.log("Інформація про користувача отримана:", user_data.data);
            return res.json({
                message: "Ви успішно увійшли!",
                user_data: user_data.data.email
            });
        } catch (err) {
            console.error("Не вдалося отримати інформацію про користувача:", err.response?.data || err.message);
            return res.status(401).json({ error: "Недійсний токен авторизації!" });
        }
    }

    console.log("Відсутній заголовок авторизації, відправка index.html");
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    console.log(`Отримано запит на вхід для користувача: ${login}`);

    const body = {
        grant_type: "password",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        username: login,
        password: password,
        scope: "offline_access openid email",
        audience: `${OAUTH_URL}/api/v2/`,
        connection: "Username-Password-Authentication"
    };

    console.log("Формується тіло запиту для Auth0:", JSON.stringify(body, null, 2));

    try {
        console.log("Надсилається запит токена до Auth0...");
        
        const authResponse = await axios.post(`${OAUTH_URL}/oauth/token`, body);
    
        console.log("Відповідь від Auth0 отримана:");
        console.log("Статус відповіді:", authResponse.status);
        console.log("Дані відповіді:", JSON.stringify(authResponse.data, null, 2));
    
        res.json({
            accessToken: authResponse.data.access_token,
            refreshToken: authResponse.data.refresh_token
        });
    
    } catch (err) {
        console.error("Помилка входу:");
        if (err.response) {
            console.error("Статус помилки:", err.response.status);
            console.error("Тіло помилки:", JSON.stringify(err.response.data, null, 2));
        } else {
            console.error("Помилка без відповіді сервера:", err.message);
        }
        
        res.status(401).json({ message: "Недійсні облікові дані" });
    }
    
});

app.get('/api/userinfo', async (req, res) => {
    const token = req.get("Authorization");

    if (!token) {
        console.log("Відсутній токен у запиті на /api/userinfo");
        return res.status(401).json({ error: "Токен не надано" });
    }

    try {
        console.log("Запит інформації про користувача з токеном:", token);
        const response = await axios.get(`${OAUTH_URL}/userinfo`, {
            headers: { Authorization: `Bearer ${token}` }
        });
        console.log("Інформація про користувача успішно отримана:", response.data);
        res.json(response.data);
    } catch (error) {
        console.error("Помилка при отриманні інформації про користувача:", error.response?.data || error.message);
        res.status(500).json({ error: "Не вдалося отримати інформацію про користувача" });
    }
});

app.listen(port, () => {
    console.log(`Сервер працює на http://localhost:${port}`);
});
