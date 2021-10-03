const PythonShell = require('python-shell').PythonShell;

async function mfa() {
    const { success, err = '', results } = await new Promise((resolve, reject) => {
        PythonShell.run('mfa.py', null, function (err, results) {
            if (err) {
                reject({ success: false, err});
            }
            console.log('results: %j', results);
            resolve({ success: true, results});
        });
    });
} 

mfa();

/*
PythonShell.run('mfa.py', null, function (err, results) {
  if (err) throw err;
  console.log('results: %j', results);
  console.log('finished');
});
*/