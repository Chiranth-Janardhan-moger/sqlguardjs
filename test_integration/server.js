const express = require('express');
const { sqlguardjs } = require('sqlguardjs');

const app = express();
const guard = sqlguardjs({ threshold: 0.5 });

app.use(express.json());
app.use(guard.global());

app.post('/login', (req, res) => {
  res.json({ success: true, message: "Logged in successfully!" });
});

app.listen(3000, () => console.log('Test Express Server running on port 3000'));
