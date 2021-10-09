const { spawn } = require('child_process');
const express = require("express");
const app = express();

const pythonPromise = () => {
    return new Promise((resolve, reject) => {
      const python = spawn("python", ["mfa.py"]);
      python.stdout.on("data", (data) => {
        resolve(data.toString());
      });
  
      python.stderr.on("data", (data) => {
        reject(data.toString());
      });
   });
  };
  app.get("/", async (req, res) => {
    const dataFromPython = await pythonPromise();
    res.send(dataFromPython);
  });
  app.listen(3000, () => console.log("App is running port 3000"));