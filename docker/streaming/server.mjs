
import http from 'http';
import fs from 'fs/promises';

async function* generateData() {
    for (let i = 0; i < 10; i++) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate delay
        yield `Data chunk ${i}\n`;
    }
}

const returnStream = async ( res ) => {
    res.writeHead(200, {
        'Content-Type': 'text/plain',
        'Transfer-Encoding': 'chunked'
    });

    for await (const chunk of generateData()) {
        res.write(chunk);
        console.log(`Sent: ${chunk}`);
    }
    res.end();
}

const returnFile = async ( res, filename, mimetype ) => {
    const data = await fs.readFile(filename);
    res.writeHead(200, {
        'Content-Type': mimetype,
    });
    res.end( data );
}

const server = http.createServer(async (req, res) => {
    console.log(req.url);
    
    switch( req.url  ) {
        case '/stream' : 
            await returnStream( res )
            break;
        case '/' :
            await returnFile( res, 'index.html', 'text/html');
            break;
        case '/client.mjs' :
            await returnFile( res, 'client.mjs', 'text/javascript');
            break;
        default :
            res.writeHead(404);
            res.end();
    }

});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});
