const express = require("express");
const http = require("http");
const crypto = require("crypto");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

/* ========================================
   CONFIGURAÇÃO
======================================== */

const PORT = process.env.PORT || 3000;

const SOCKET_PATH = "/hunt-socket";

const ACCESS_TOKEN_DURATION =
  6 * 60 * 60 * 1000;

/* ========================================
   CORS
======================================== */

/*
 * O cliente e o servidor estão em
 * domínios diferentes no Render.
 *
 * Por isso precisamos liberar as
 * requisições HTTP da aplicação cliente.
 */

const ALLOWED_ORIGINS = [
  "https://hunt-screen-client.onrender.com",
  "http://localhost:5173",
  "http://127.0.0.1:5173"
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  /*
   * Permite as origens conhecidas.
   *
   * Se não houver Origin, como em uma
   * abertura direta pelo navegador ou
   * alguma requisição interna, seguimos
   * normalmente.
   */

  if (
    !origin ||
    ALLOWED_ORIGINS.includes(origin)
  ) {
    if (origin) {
      res.setHeader(
        "Access-Control-Allow-Origin",
        origin
      );
    }
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  );

  /*
   * Responder preflight do navegador.
   */

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

/* ========================================
   SOCKET.IO
======================================== */

const io = new Server(server, {
  path: SOCKET_PATH,

  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST"]
  },

  transports: [
    "polling",
    "websocket"
  ]
});

/* ========================================
   MIDDLEWARE
======================================== */

app.use(express.json());

/* ========================================
   SALAS
======================================== */

/*
 * rooms:
 *
 * roomId -> {
 *   id,
 *   name,
 *   passwordHash,
 *   passwordSalt,
 *   broadcaster,
 *   viewers: Set,
 *   createdAt
 * }
 */

const rooms = new Map();

/* ========================================
   TRANSMISSORES
======================================== */

/*
 * roomId -> socketId
 */

const broadcasters = new Map();

/* ========================================
   TOKENS
======================================== */

/*
 * token -> {
 *   roomId,
 *   socketId,
 *   role,
 *   createdAt
 * }
 */

const accessTokens = new Map();

/* ========================================
   TESTE DO SERVIDOR
======================================== */

app.get("/", (req, res) => {
  res
    .status(200)
    .send("HUNT SERVER ONLINE");
});

/* ========================================
   HEALTH CHECK
======================================== */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "online",
    rooms: rooms.size,
    timestamp: Date.now()
  });
});

/* ========================================
   GERAR ID DA SALA
======================================== */

function generateRoomId() {
  let roomId;

  do {
    roomId = crypto
      .randomBytes(6)
      .toString("hex");
  } while (rooms.has(roomId));

  return roomId;
}

/* ========================================
   GERAR TOKEN
======================================== */

function generateAccessToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

/* ========================================
   HASH DA SENHA
======================================== */

function hashPassword(password, salt) {
  return crypto
    .scryptSync(
      password,
      salt,
      64
    )
    .toString("hex");
}

/* ========================================
   CRIAR HASH DA SENHA
======================================== */

function createPasswordHash(password) {
  const salt =
    crypto
      .randomBytes(16)
      .toString("hex");

  const hash =
    hashPassword(
      password,
      salt
    );

  return {
    salt,
    hash
  };
}

/* ========================================
   VERIFICAR SENHA
======================================== */

function verifyPassword(password, room) {
  if (
    typeof password !== "string" ||
    !room ||
    !room.passwordHash ||
    !room.passwordSalt
  ) {
    return false;
  }

  try {
    const hash =
      hashPassword(
        password,
        room.passwordSalt
      );

    const received =
      Buffer.from(
        hash,
        "hex"
      );

    const stored =
      Buffer.from(
        room.passwordHash,
        "hex"
      );

    if (
      received.length !==
      stored.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      received,
      stored
    );

  } catch {
    return false;
  }
}

/* ========================================
   CRIAR TOKEN DE ACESSO
======================================== */

function createRoomAccessToken(
  roomId,
  role = "viewer"
) {
  const token =
    generateAccessToken();

  accessTokens.set(
    token,
    {
      roomId,
      role,
      socketId: null,
      createdAt: Date.now()
    }
  );

  return token;
}

/* ========================================
   VALIDAR TOKEN
======================================== */

function validateAccessToken(
  token,
  roomId,
  role = null,
  socketId = null
) {
  if (
    typeof token !== "string" ||
    !token
  ) {
    return false;
  }

  const access =
    accessTokens.get(token);

  if (!access) {
    return false;
  }

  /* ================================
     EXPIRAÇÃO
  ================================= */

  if (
    Date.now() -
      access.createdAt >
    ACCESS_TOKEN_DURATION
  ) {
    accessTokens.delete(token);

    return false;
  }

  /* ================================
     SALA
  ================================= */

  if (
    access.roomId !==
    roomId
  ) {
    return false;
  }

  /* ================================
     FUNÇÃO
  ================================= */

  if (
    role &&
    access.role !== role
  ) {
    return false;
  }

  /* ================================
     SOCKET
  ================================= */

  /*
   * Quando o token ainda não foi usado
   * por nenhum socket, permitimos o primeiro
   * socket e ele será associado logo depois.
   */

  if (
    access.socketId &&
    socketId &&
    access.socketId !== socketId
  ) {
    return false;
  }

  return true;
}

/* ========================================
   ASSOCIAR TOKEN AO SOCKET
======================================== */

function bindTokenToSocket(
  token,
  socketId
) {
  if (!token) {
    return false;
  }

  const access =
    accessTokens.get(token);

  if (!access) {
    return false;
  }

  /*
   * Se já pertence a outro socket,
   * não permitimos reutilização.
   */

  if (
    access.socketId &&
    access.socketId !== socketId
  ) {
    return false;
  }

  access.socketId =
    socketId;

  return true;
}

/* ========================================
   REMOVER TOKENS DA SALA
======================================== */

function removeRoomTokens(roomId) {
  for (
    const [
      token,
      access
    ]
    of accessTokens
  ) {
    if (
      access.roomId ===
      roomId
    ) {
      accessTokens.delete(
        token
      );
    }
  }
}

/* ========================================
   REMOVER TOKEN DE SOCKET
======================================== */

function removeSocketToken(socketId) {
  for (
    const [
      token,
      access
    ]
    of accessTokens
  ) {
    if (
      access.socketId ===
      socketId
    ) {
      accessTokens.delete(
        token
      );
    }
  }
}

/* ========================================
   VERIFICAR SOCKET NA SALA
======================================== */

function socketBelongsToRoom(
  socket,
  roomId
) {
  return (
    socket &&
    socket.huntRoomId ===
      roomId
  );
}

/* ========================================
   VERIFICAR ACESSO DO SOCKET
======================================== */

function socketHasRoomAccess(
  socket,
  roomId,
  role = null
) {
  if (!socket) {
    return false;
  }

  if (
    socket.huntRoomId !==
    roomId
  ) {
    return false;
  }

  if (
    role &&
    socket.huntRole !==
    role
  ) {
    return false;
  }

  return validateAccessToken(
    socket.huntAccessToken,
    roomId,
    role,
    socket.id
  );
}

/* ========================================
   LISTAR SALAS
======================================== */

app.get(
  "/api/rooms",
  (req, res) => {
    try {
      const result = [];

      for (
        const room
        of rooms.values()
      ) {
        result.push({
          id: room.id,

          name: room.name,

          live:
            Boolean(
              room.broadcaster
            ),

          viewers:
            room.viewers.size,

          createdAt:
            room.createdAt
        });
      }

      /*
       * Salas mais recentes primeiro.
       */

      result.sort(
        (a, b) =>
          b.createdAt -
          a.createdAt
      );

      res.json({
        success: true,
        rooms: result
      });

    } catch (error) {
      console.error(
        "HUNT: erro listando salas:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Erro interno ao listar salas."
        });
    }
  }
);

/* ========================================
   CRIAR SALA
======================================== */

app.post(
  "/api/rooms",
  (req, res) => {
    try {
      const name =
        typeof req.body?.name ===
        "string"
          ? req.body.name.trim()
          : "";

      const password =
        typeof req.body?.password ===
        "string"
          ? req.body.password
          : "";

      /* ================================
         NOME
      ================================= */

      if (!name) {
        return res
          .status(400)
          .json({
            error:
              "Informe o nome da sala."
          });
      }

      if (name.length > 50) {
        return res
          .status(400)
          .json({
            error:
              "O nome da sala deve ter no máximo 50 caracteres."
          });
      }

      /* ================================
         SENHA
      ================================= */

      if (!password) {
        return res
          .status(400)
          .json({
            error:
              "Informe uma senha."
          });
      }

      if (password.length < 4) {
        return res
          .status(400)
          .json({
            error:
              "A senha deve ter pelo menos 4 caracteres."
          });
      }

      if (password.length > 100) {
        return res
          .status(400)
          .json({
            error:
              "A senha é muito longa."
          });
      }

      /* ================================
         GERAR SALA
      ================================= */

      const roomId =
        generateRoomId();

      const passwordData =
        createPasswordHash(
          password
        );

      const room = {
        id: roomId,

        name,

        passwordHash:
          passwordData.hash,

        passwordSalt:
          passwordData.salt,

        broadcaster: null,

        viewers:
          new Set(),

        createdAt:
          Date.now()
      };

      rooms.set(
        roomId,
        room
      );

      console.log(
        `HUNT: sala criada: ${name} (${roomId})`
      );

      res
        .status(201)
        .json({
          success: true,

          room: {
            id: room.id,

            name: room.name,

            live: false,

            viewers: 0,

            createdAt:
              room.createdAt
          }
        });

    } catch (error) {
      console.error(
        "HUNT: erro criando sala:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Erro interno ao criar sala."
        });
    }
  }
);

/* ========================================
   ENTRAR NA SALA / VALIDAR SENHA
======================================== */

app.post(
  "/api/rooms/:roomId/join",
  (req, res) => {
    try {
      const roomId =
        req.params.roomId;

      const password =
        typeof req.body?.password ===
        "string"
          ? req.body.password
          : "";

      const requestedRole =
        req.body?.role ===
        "broadcaster"
          ? "broadcaster"
          : "viewer";

      /* ================================
         SALA
      ================================= */

      const room =
        rooms.get(
          roomId
        );

      if (!room) {
        return res
          .status(404)
          .json({
            error:
              "Sala não encontrada."
          });
      }

      /* ================================
         SENHA
      ================================= */

      if (
        !verifyPassword(
          password,
          room
        )
      ) {
        return res
          .status(401)
          .json({
            error:
              "Senha incorreta."
          });
      }

      /* ================================
         TRANSMISSOR
      ================================= */

      if (
        requestedRole ===
          "broadcaster" &&
        room.broadcaster
      ) {
        return res
          .status(409)
          .json({
            error:
              "Esta sala já possui um transmissor."
          });
      }

      /* ================================
         TOKEN
      ================================= */

      const accessToken =
        createRoomAccessToken(
          roomId,
          requestedRole
        );

      console.log(
        `HUNT: acesso autorizado para ${roomId} como ${requestedRole}`
      );

      res.json({
        success: true,

        accessToken,

        room: {
          id: room.id,

          name: room.name,

          live:
            Boolean(
              room.broadcaster
            ),

          viewers:
            room.viewers.size
        }
      });

    } catch (error) {
      console.error(
        "HUNT: erro entrando na sala:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Erro interno ao entrar na sala."
        });
    }
  }
);

/* ========================================
   SOCKET.IO
======================================== */

io.on(
  "connection",
  (socket) => {
    console.log(
      "HUNT: cliente conectado:",
      socket.id
    );

    /* ====================================
       ENTRAR NA SALA
    ==================================== */

    socket.on(
      "join-room",
      (data) => {
        try {
          let roomId = null;

          let accessToken = null;

          let role = "viewer";

          /* ================================
             FORMATO NOVO
          ================================= */

          if (
            data &&
            typeof data ===
              "object"
          ) {
            roomId =
              data.roomId ||
              null;

            accessToken =
              data.accessToken ||
              null;

            role =
              data.role ===
              "broadcaster"
                ? "broadcaster"
                : "viewer";
          }

          /*
           * O formato antigo por string
           * não é mais aceito.
           *
           * O sistema agora utiliza
           * salas protegidas por senha.
           */

          if (
            typeof data ===
            "string"
          ) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "PASSWORD_REQUIRED"
              }
            );

            return;
          }

          if (!roomId) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "ROOM_ID_MISSING"
              }
            );

            return;
          }

          /* ================================
             SALA
          ================================= */

          const room =
            rooms.get(
              roomId
            );

          if (!room) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "ROOM_NOT_FOUND"
              }
            );

            return;
          }

          /* ================================
             TOKEN
          ================================= */

          const validToken =
            validateAccessToken(
              accessToken,
              roomId,
              role,
              socket.id
            );

          if (!validToken) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "INVALID_ACCESS_TOKEN"
              }
            );

            return;
          }

          /* ================================
             VINCULAR TOKEN
          ================================= */

          if (
            !bindTokenToSocket(
              accessToken,
              socket.id
            )
          ) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "TOKEN_ALREADY_IN_USE"
              }
            );

            return;
          }

          /* ================================
             IMPEDIR SEGUNDO TRANSMISSOR
          ================================= */

          if (
            role ===
              "broadcaster" &&
            room.broadcaster &&
            room.broadcaster !==
              socket.id
          ) {
            socket.emit(
              "stream-already-started",
              {
                broadcasterId:
                  room.broadcaster
              }
            );

            return;
          }

          /* ================================
             SAIR DA SALA ANTERIOR
          ================================= */

          if (
            socket.huntRoomId &&
            socket.huntRoomId !==
              roomId
          ) {
            const oldRoom =
              rooms.get(
                socket.huntRoomId
              );

            if (oldRoom) {
              oldRoom.viewers.delete(
                socket.id
              );
            }

            socket.leave(
              socket.huntRoomId
            );
          }

          /* ================================
             ENTRAR
          ================================= */

          socket.join(
            roomId
          );

          socket.huntRoomId =
            roomId;

          socket.huntAccessToken =
            accessToken;

          socket.huntRole =
            role;

          /* ================================
             VIEWER
          ================================= */

          if (
            role ===
            "viewer"
          ) {
            room.viewers.add(
              socket.id
            );
          }

          /* ================================
             BROADCASTER
          ================================= */

          if (
            role ===
            "broadcaster"
          ) {
            /*
             * Entrar na sala não começa
             * a transmissão automaticamente.
             */

            if (
              room.broadcaster &&
              room.broadcaster !==
                socket.id
            ) {
              socket.emit(
                "stream-already-started",
                {
                  broadcasterId:
                    room.broadcaster
                }
              );

              return;
            }
          }

          console.log(
            `HUNT: ${socket.id} entrou em ${roomId} como ${role}`
          );

          /* ================================
             TRANSMISSÃO JÁ EXISTENTE
          ================================= */

          const broadcaster =
            broadcasters.get(
              roomId
            );

          if (
            broadcaster &&
            broadcaster !==
              socket.id
          ) {
            socket.emit(
              "stream-started",
              {
                broadcasterId:
                  broadcaster
              }
            );

            io.to(
              broadcaster
            ).emit(
              "user-joined",
              {
                socketId:
                  socket.id
              }
            );
          }

        } catch (error) {
          console.error(
            "HUNT: erro em join-room:",
            error
          );

          socket.emit(
            "room-access-denied",
            {
              reason:
                "INTERNAL_ERROR"
            }
          );
        }
      }
    );

    /* ====================================
       COMEÇAR TRANSMISSÃO
    ==================================== */

    socket.on(
      "start-stream",
      (data) => {
        try {
          const roomId =
            data?.roomId ||
            socket.huntRoomId ||
            null;

          const accessToken =
            data?.accessToken ||
            socket.huntAccessToken ||
            null;

          if (!roomId) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "ROOM_ID_MISSING"
              }
            );

            return;
          }

          const room =
            rooms.get(
              roomId
            );

          if (!room) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "ROOM_NOT_FOUND"
              }
            );

            return;
          }

          /* ================================
             SOCKET NA SALA
          ================================= */

          if (
            !socketBelongsToRoom(
              socket,
              roomId
            )
          ) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "NOT_IN_ROOM"
              }
            );

            return;
          }

          /* ================================
             PAPEL
          ================================= */

          if (
            socket.huntRole !==
            "broadcaster"
          ) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "BROADCASTER_ONLY"
              }
            );

            return;
          }

          /* ================================
             TOKEN
          ================================= */

          if (
            !validateAccessToken(
              accessToken,
              roomId,
              "broadcaster",
              socket.id
            )
          ) {
            socket.emit(
              "room-access-denied",
              {
                reason:
                  "INVALID_ACCESS_TOKEN"
              }
            );

            return;
          }

          /* ================================
             IMPEDIR DUPLICAÇÃO
          ================================= */

          const existingBroadcaster =
            broadcasters.get(
              roomId
            );

          if (
            existingBroadcaster &&
            existingBroadcaster !==
              socket.id
          ) {
            socket.emit(
              "stream-already-started",
              {
                broadcasterId:
                  existingBroadcaster
              }
            );

            return;
          }

          /* ================================
             REGISTRAR
          ================================= */

          broadcasters.set(
            roomId,
            socket.id
          );

          room.broadcaster =
            socket.id;

          console.log(
            `HUNT: ${socket.id} começou a transmitir em ${roomId}`
          );

          /* ================================
             AVISAR ESPECTADORES
          ================================= */

          socket
            .to(roomId)
            .emit(
              "stream-started",
              {
                broadcasterId:
                  socket.id
              }
            );

          /*
           * Confirmação para o transmissor.
           */

          socket.emit(
            "stream-started",
            {
              broadcasterId:
                socket.id,

              local: true
            }
          );

        } catch (error) {
          console.error(
            "HUNT: erro em start-stream:",
            error
          );
        }
      }
    );

    /* ====================================
       WEBRTC OFFER
    ==================================== */

    socket.on(
      "webrtc-offer",
      (data) => {
        try {
          if (
            !data ||
            !data.target ||
            !data.offer
          ) {
            return;
          }

          const roomId =
            socket.huntRoomId;

          if (!roomId) {
            return;
          }

          const room =
            rooms.get(
              roomId
            );

          if (!room) {
            return;
          }

          /*
           * Somente o transmissor
           * pode enviar OFFER.
           */

          if (
            room.broadcaster !==
            socket.id
          ) {
            return;
          }

          if (
            !socketHasRoomAccess(
              socket,
              roomId,
              "broadcaster"
            )
          ) {
            return;
          }

          const targetSocket =
            io.sockets.sockets.get(
              data.target
            );

          if (!targetSocket) {
            return;
          }

          /*
           * O alvo precisa estar na
           * mesma sala como viewer.
           */

          if (
            targetSocket.huntRoomId !==
              roomId ||
            targetSocket.huntRole !==
              "viewer"
          ) {
            return;
          }

          console.log(
            `HUNT: OFFER ${socket.id} -> ${data.target}`
          );

          io.to(
            data.target
          ).emit(
            "webrtc-offer",
            {
              sender:
                socket.id,

              offer:
                data.offer
            }
          );

        } catch (error) {
          console.error(
            "HUNT: erro encaminhando OFFER:",
            error
          );
        }
      }
    );

    /* ====================================
       WEBRTC ANSWER
    ==================================== */

    socket.on(
      "webrtc-answer",
      (data) => {
        try {
          if (
            !data ||
            !data.target ||
            !data.answer
          ) {
            return;
          }

          const roomId =
            socket.huntRoomId;

          if (!roomId) {
            return;
          }

          const room =
            rooms.get(
              roomId
            );

          if (!room) {
            return;
          }

          /*
           * Apenas viewers podem
           * responder.
           */

          if (
            socket.huntRole !==
            "viewer"
          ) {
            return;
          }

          if (
            !socketHasRoomAccess(
              socket,
              roomId,
              "viewer"
            )
          ) {
            return;
          }

          /*
           * O destino precisa ser
           * o transmissor da sala.
           */

          if (
            room.broadcaster !==
            data.target
          ) {
            return;
          }

          const targetSocket =
            io.sockets.sockets.get(
              data.target
            );

          if (!targetSocket) {
            return;
          }

          if (
            targetSocket.huntRoomId !==
              roomId ||
            targetSocket.huntRole !==
              "broadcaster"
          ) {
            return;
          }

          console.log(
            `HUNT: ANSWER ${socket.id} -> ${data.target}`
          );

          io.to(
            data.target
          ).emit(
            "webrtc-answer",
            {
              sender:
                socket.id,

              answer:
                data.answer
            }
          );

        } catch (error) {
          console.error(
            "HUNT: erro encaminhando ANSWER:",
            error
          );
        }
      }
    );

    /* ====================================
       ICE CANDIDATE
    ==================================== */

    socket.on(
      "webrtc-ice-candidate",
      (data) => {
        try {
          if (
            !data ||
            !data.target ||
            !data.candidate
          ) {
            return;
          }

          const roomId =
            socket.huntRoomId;

          if (!roomId) {
            return;
          }

          const room =
            rooms.get(
              roomId
            );

          if (!room) {
            return;
          }

          const targetSocket =
            io.sockets.sockets.get(
              data.target
            );

          if (!targetSocket) {
            return;
          }

          if (
            targetSocket.huntRoomId !==
            roomId
          ) {
            return;
          }

          /*
           * ICE somente entre
           * transmissor e viewer.
           */

          const broadcasterSending =
            socket.id ===
              room.broadcaster &&
            targetSocket.huntRole ===
              "viewer";

          const viewerSending =
            socket.huntRole ===
              "viewer" &&
            targetSocket.id ===
              room.broadcaster;

          if (
            !broadcasterSending &&
            !viewerSending
          ) {
            return;
          }

          /*
           * Verificar acesso do emissor.
           */

          const senderRole =
            socket.id ===
            room.broadcaster
              ? "broadcaster"
              : "viewer";

          if (
            !socketHasRoomAccess(
              socket,
              roomId,
              senderRole
            )
          ) {
            return;
          }

          io.to(
            data.target
          ).emit(
            "webrtc-ice-candidate",
            {
              sender:
                socket.id,

              candidate:
                data.candidate
            }
          );

        } catch (error) {
          console.error(
            "HUNT: erro encaminhando ICE:",
            error
          );
        }
      }
    );

    /* ====================================
       SAIR DA SALA
    ==================================== */

    socket.on(
      "leave-room",
      (data) => {
        const roomId =
          data?.roomId ||
          socket.huntRoomId ||
          null;

        if (!roomId) {
          return;
        }

        leaveRoom(
          socket,
          roomId
        );
      }
    );

    /* ====================================
       PARAR TRANSMISSÃO
    ==================================== */

    socket.on(
      "stop-stream",
      (data) => {
        try {
          const roomId =
            data?.roomId ||
            socket.huntRoomId ||
            null;

          if (!roomId) {
            return;
          }

          const room =
            rooms.get(
              roomId
            );

          if (!room) {
            return;
          }

          /*
           * Somente o transmissor
           * atual pode parar.
           */

          if (
            broadcasters.get(
              roomId
            ) !==
            socket.id
          ) {
            return;
          }

          if (
            !socketHasRoomAccess(
              socket,
              roomId,
              "broadcaster"
            )
          ) {
            return;
          }

          /* ================================
             REMOVER TRANSMISSÃO
          ================================= */

          broadcasters.delete(
            roomId
          );

          room.broadcaster =
            null;

          console.log(
            `HUNT: ${socket.id} parou a transmissão em ${roomId}`
          );

          socket
            .to(roomId)
            .emit(
              "stream-stopped",
              {
                broadcasterId:
                  socket.id
              }
            );

          /*
           * A sala é encerrada junto
           * com o transmissor.
           */

          removeRoom(
            roomId
          );

        } catch (error) {
          console.error(
            "HUNT: erro em stop-stream:",
            error
          );
        }
      }
    );

    /* ====================================
       DESCONECTAR
    ==================================== */

    socket.on(
      "disconnect",
      () => {
        try {
          console.log(
            "HUNT: cliente desconectado:",
            socket.id
          );

          /* ================================
             TRANSMISSOR
          ================================= */

          const roomsToRemove = [];

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

              const room =
                rooms.get(
                  roomId
                );

              if (room) {
                room.broadcaster =
                  null;

                socket
                  .to(roomId)
                  .emit(
                    "stream-stopped",
                    {
                      broadcasterId:
                        socket.id
                    }
                  );

                roomsToRemove.push(
                  roomId
                );
              }
            }
          }

          /* ================================
             REMOVER SALAS
          ================================= */

          for (
            const roomId
            of roomsToRemove
          ) {
            removeRoom(
              roomId
            );
          }

          /* ================================
             VIEWER
          ================================= */

          if (
            socket.huntRoomId
          ) {
            const room =
              rooms.get(
                socket.huntRoomId
              );

            if (room) {
              room.viewers.delete(
                socket.id
              );
            }
          }

          /* ================================
             TOKEN
          ================================= */

          removeSocketToken(
            socket.id
          );

        } catch (error) {
          console.error(
            "HUNT: erro durante disconnect:",
            error
          );
        }
      }
    );
  }
);

/* ========================================
   SAIR DA SALA
======================================== */

function leaveRoom(
  socket,
  roomId
) {
  const room =
    rooms.get(
      roomId
    );

  if (!room) {
    socket.leave(
      roomId
    );

    return;
  }

  /* ======================================
     TRANSMISSOR
  ====================================== */

  if (
    room.broadcaster ===
    socket.id
  ) {
    broadcasters.delete(
      roomId
    );

    room.broadcaster =
      null;

    socket
      .to(roomId)
      .emit(
        "stream-stopped",
        {
          broadcasterId:
            socket.id
        }
      );

    socket.leave(
      roomId
    );

    socket.huntRoomId =
      null;

    socket.huntRole =
      null;

    socket.huntAccessToken =
      null;

    removeRoom(
      roomId
    );

    return;
  }

  /* ======================================
     VIEWER
  ====================================== */

  room.viewers.delete(
    socket.id
  );

  socket.leave(
    roomId
  );

  socket.huntRoomId =
    null;

  socket.huntRole =
    null;

  socket.huntAccessToken =
    null;

  console.log(
    `HUNT: ${socket.id} saiu da sala ${roomId}`
  );

  /*
   * Se não houver transmissor e
   * não houver viewers, remover.
   */

  if (
    !room.broadcaster &&
    room.viewers.size === 0
  ) {
    removeRoom(
      roomId
    );
  }
}

/* ========================================
   REMOVER SALA
======================================== */

function removeRoom(
  roomId
) {
  const room =
    rooms.get(
      roomId
    );

  if (!room) {
    return;
  }

  /*
   * Nunca remover uma sala que
   * ainda possui transmissor.
   */

  if (
    room.broadcaster
  ) {
    return;
  }

  /*
   * Avisar clientes.
   */

  io.to(
    roomId
  ).emit(
    "room-closed",
    {
      roomId
    }
  );

  /*
   * Remover tokens.
   */

  removeRoomTokens(
    roomId
  );

  /*
   * Remover broadcaster map.
   */

  broadcasters.delete(
    roomId
  );

  /*
   * Remover sala.
   */

  rooms.delete(
    roomId
  );

  console.log(
    `HUNT: sala removida: ${roomId}`
  );
}

/* ========================================
   LIMPEZA DE TOKENS
======================================== */

setInterval(
  () => {
    const now =
      Date.now();

    for (
      const [
        token,
        access
      ]
      of accessTokens
    ) {
      if (
        now -
          access.createdAt >
        ACCESS_TOKEN_DURATION
      ) {
        accessTokens.delete(
          token
        );
      }
    }
  },
  60 * 1000
);

/* ========================================
   LIMPEZA DE SALAS VAZIAS
======================================== */

setInterval(
  () => {
    for (
      const [
        roomId,
        room
      ]
      of rooms
    ) {
      /*
       * Sala criada mas que nunca
       * recebeu transmissor ou viewer.
       */

      if (
        !room.broadcaster &&
        room.viewers.size === 0
      ) {
        removeRoom(
          roomId
        );
      }
    }
  },
  5 * 60 * 1000
);

/* ========================================
   INICIAR SERVIDOR
======================================== */

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `HUNT SERVER rodando na porta ${PORT}`
    );

    console.log(
      `HUNT SOCKET ativo em ${SOCKET_PATH}`
    );

    console.log(
      "HUNT: sistema de salas ativo."
    );
  }
);
