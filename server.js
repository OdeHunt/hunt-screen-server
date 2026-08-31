const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});


/* ================================
   CONFIGURAÇÃO
================================ */

const PORT = process.env.PORT || 3000;

const broadcasters = new Map();


/* ================================
   TESTE DO SERVIDOR
================================ */

app.get("/", (req, res) => {
  res.status(200).send("HUNT SERVER ONLINE");
});


/* ================================
   SOCKET.IO
================================ */

io.on("connection", (socket) => {

  console.log("Cliente conectado:", socket.id);


  /* ================================
     ENTRAR NA SALA
  ================================= */

  socket.on("join-room", (roomId) => {

    if (!roomId) {
      console.log(
        "HUNT: tentativa de entrar sem roomId"
      );
      return;
    }

    console.log(
      `${socket.id} entrou na sala ${roomId}`
    );

    socket.join(roomId);


    /*
     * Verificar se já existe
     * um transmissor.
     */

    const broadcaster =
      broadcasters.get(roomId);


    if (broadcaster) {

      console.log(
        "Transmissão já existente:",
        broadcaster
      );


      /*
       * Avisar o espectador
       * que existe transmissão.
       */

      socket.emit(
        "stream-started",
        {
          broadcasterId: broadcaster
        }
      );


      /*
       * Avisar o transmissor
       * que um novo espectador entrou.
       */

      io.to(broadcaster).emit(
        "user-joined",
        {
          socketId: socket.id
        }
      );

    }

  });


  /* ================================
     COMEÇAR TRANSMISSÃO
  ================================= */

  socket.on(
    "start-stream",
    (data) => {

      console.log(
        "HUNT: start-stream recebido:",
        socket.id
      );


      const roomId =
        data &&
        data.roomId;


      if (!roomId) {

        console.log(
          "HUNT: roomId não informado"
        );

        return;
      }


      /*
       * Registrar transmissor.
       */

      broadcasters.set(
        roomId,
        socket.id
      );


      /*
       * Avisar os outros usuários.
       */

      socket
        .to(roomId)
        .emit(
          "stream-started",
          {
            broadcasterId: socket.id
          }
        );


      console.log(
        `HUNT: ${socket.id} está transmitindo na sala ${roomId}`
      );

    }
  );


  /* ================================
     WEBRTC OFFER
  ================================= */

  socket.on(
    "webrtc-offer",
    (data) => {

      if (
        !data ||
        !data.target ||
        !data.offer
      ) {

        console.log(
          "HUNT: OFFER inválida"
        );

        return;
      }


      console.log(
        "HUNT: encaminhando OFFER:",
        socket.id,
        "→",
        data.target
      );


      io.to(
        data.target
      ).emit(
        "webrtc-offer",
        {
          sender: socket.id,
          offer: data.offer
        }
      );

    }
  );


  /* ================================
     WEBRTC ANSWER
  ================================= */

  socket.on(
    "webrtc-answer",
    (data) => {

      if (
        !data ||
        !data.target ||
        !data.answer
      ) {

        console.log(
          "HUNT: ANSWER inválida"
        );

        return;
      }


      console.log(
        "HUNT: encaminhando ANSWER:",
        socket.id,
        "→",
        data.target
      );


      io.to(
        data.target
      ).emit(
        "webrtc-answer",
        {
          sender: socket.id,
          answer: data.answer
        }
      );

    }
  );


  /* ================================
     ICE CANDIDATE
  ================================= */

  socket.on(
    "webrtc-ice-candidate",
    (data) => {

      if (
        !data ||
        !data.target ||
        !data.candidate
      ) {

        console.log(
          "HUNT: ICE inválido"
        );

        return;
      }


      console.log(
        "HUNT: encaminhando ICE:",
        socket.id,
        "→",
        data.target
      );


      io.to(
        data.target
      ).emit(
        "webrtc-ice-candidate",
        {
          sender: socket.id,
          candidate: data.candidate
        }
      );

    }
  );


  /* ================================
     PARAR TRANSMISSÃO
  ================================= */

  socket.on(
    "stop-stream",
    (data) => {

      const roomId =
        data &&
        data.roomId;


      if (!roomId) {
        return;
      }


      /*
       * Só o transmissor atual
       * pode encerrar a transmissão.
       */

      if (
        broadcasters.get(roomId) !==
        socket.id
      ) {

        return;
      }


      broadcasters.delete(
        roomId
      );


      socket
        .to(roomId)
        .emit(
          "stream-stopped",
          {
            broadcasterId: socket.id
          }
        );


      console.log(
        `HUNT: transmissão encerrada na sala ${roomId}`
      );

    }
  );


  /* ================================
     DESCONECTAR
  ================================= */

  socket.on(
    "disconnect",
    () => {

      console.log(
        "Cliente desconectado:",
        socket.id
      );


      /*
       * Verificar se o cliente
       * era algum transmissor.
       */

      for (
        const [
          roomId,
          broadcasterId
        ]
        of broadcasters
      ) {

        if (
          broadcasterId ===
          socket.id
        ) {

          broadcasters.delete(
            roomId
          );


          socket
            .to(roomId)
            .emit(
              "stream-stopped",
              {
                broadcasterId: socket.id
              }
            );


          console.log(
            `HUNT: transmissão removida da sala ${roomId}`
          );

        }

      }

    }
  );

});


/* ================================
   INICIAR SERVIDOR
================================ */

server.listen(
  PORT,
  () => {

    console.log(
      `HUNT SERVER rodando na porta ${PORT}`
    );

  }
);