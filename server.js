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

/*
 * Sala vazia por 10 minutos:
 * remove automaticamente.
 */

const EMPTY_ROOM_TIMEOUT =
  10 * 60 * 1000;

/*
 * Intervalo de verificação:
 * 30 segundos.
 */

const ROOM_CLEANUP_INTERVAL =
  30 * 1000;

/* ========================================
   CORS
======================================== */

const ALLOWED_ORIGINS = [
  "https://hunt-screen-client.onrender.com",
  "http://localhost:5173",
  "http://127.0.0.1:5173"
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

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
 * roomId -> {
 *
 *   id,
 *   name,
 *   passwordHash,
 *   passwordSalt,
 *
 *   broadcaster,
 *   viewers,
 *
 *   createdAt,
 *
 *   emptySince
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
 *
 *   roomId,
 *   socketId,
 *   role,
 *   createdAt
 *
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
    roomId =
      crypto
        .randomBytes(6)
        .toString("hex");

  } while (
    rooms.has(roomId)
  );

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

function hashPassword(
  password,
  salt
) {
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

function createPasswordHash(
  password
) {
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

function verifyPassword(
  password,
  room
) {
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

      createdAt:
        Date.now()
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
    accessTokens.get(
      token
    );

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
    accessTokens.delete(
      token
    );

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
    access.role !==
      role
  ) {
    return false;
  }

  /* ================================
     SOCKET
  ================================= */

  if (
    access.socketId &&
    socketId &&
    access.socketId !==
      socketId
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
    accessTokens.get(
      token
    );

  if (!access) {
    return false;
  }

  if (
    access.socketId &&
    access.socketId !==
      socketId
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

function removeRoomTokens(
  roomId
) {
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

function removeSocketToken(
  socketId
) {
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
   MARCAR SALA COMO VAZIA
======================================== */

function markRoomAsEmpty(
  room
) {
  if (!room) {
    return;
  }

  /*
   * Se já estiver contando,
   * não reinicia o contador.
   */

  if (
    room.emptySince ===
    null
  ) {
    room.emptySince =
      Date.now();

    console.log(
      `HUNT: sala ${room.id} ficou vazia. Contagem de 10 minutos iniciada.`
    );
  }
}

/* ========================================
   MARCAR SALA COMO ATIVA
======================================== */

function markRoomAsActive(
  room
) {
  if (!room) {
    return;
  }

  if (
    room.emptySince !==
    null
  ) {
    console.log(
      `HUNT: atividade detectada na sala ${room.id}. Contagem de fechamento cancelada.`
    );
  }

  room.emptySince =
    null;
}

/* ========================================
   VERIFICAR SE SALA ESTÁ VAZIA
======================================== */

function isRoomEmpty(
  room
) {
  if (!room) {
    return true;
  }

  return (
    !room.broadcaster &&
    room.viewers.size ===
      0
  );
}

/* ========================================
   ATUALIZAR ESTADO DA SALA
======================================== */

function updateRoomActivity(
  room
) {
  if (!room) {
    return;
  }

  if (
    isRoomEmpty(room)
  ) {
    markRoomAsEmpty(
      room
    );
  } else {
    markRoomAsActive(
      room
    );
  }
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
        /*
         * IMPORTANTE:
         *
         * Não enviamos viewers.
         *
         * O cliente não recebe
         * a quantidade de espectadores.
         */

        result.push({
          id: room.id,

          name: room.name,

          live:
            Boolean(
              room.broadcaster
            ),

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

      if (
        name.length >
        50
      ) {
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

      if (
        password.length <
        4
      ) {
        return res
          .status(400)
          .json({
            error:
              "A senha deve ter pelo menos 4 caracteres."
          });
      }

      if (
        password.length >
        100
      ) {
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

        broadcaster:
          null,

        viewers:
          new Set(),

        createdAt:
          Date.now(),

        /*
         * A sala começa vazia.
         *
         * Portanto os 10 minutos
         * começam a contar agora.
         */

        emptySince:
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
            )
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
          let roomId =
            null;

          let accessToken =
            null;

          let role =
            "viewer";

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

          /* ================================
             FORMATO ANTIGO
          ================================= */

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

          /* ================================
             ROOM ID
          ================================= */

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

              updateRoomActivity(
                oldRoom
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

          /*
           * A sala agora possui alguém.
           *
           * Cancela o contador de
           * sala vazia.
           */

          markRoomAsActive(
            room
          );

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

          /*
           * Existe alguém na sala,
           * então não pode haver
           * contador de sala vazia.
           */

          markRoomAsActive(
            room
          );

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

          /* ================================
             CONFIRMAÇÃO
          ================================= */

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
           * O alvo precisa estar
           * na mesma sala.
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
           * Destino precisa ser
           * o transmissor.
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
           * Verificar acesso.
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
           * IMPORTANTE:
           *
           * Não removemos a sala
           * imediatamente.
           *
           * Se ainda houver espectadores,
           * a sala continua existindo.
           *
           * Se não houver ninguém,
           * inicia a contagem de 10 minutos.
           */

          updateRoomActivity(
            room
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

          const affectedRooms =
            [];

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

                affectedRooms.push(
                  room
                );
              }
            }
          }

          /*
           * Atualizar estado das
           * salas afetadas.
           */

          for (
            const room
            of affectedRooms
          ) {
            updateRoomActivity(
              room
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

              updateRoomActivity(
                room
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

    /*
     * A sala não é mais removida
     * imediatamente.
     *
     * Se ficar vazia, inicia os
     * 10 minutos.
     */

    updateRoomActivity(
      room
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
   * Se ficou completamente vazia,
   * começa a contagem de 10 minutos.
   */

  updateRoomActivity(
    room
  );
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
   * Nunca remover uma sala
   * que ainda possui transmissor.
   */

  if (
    room.broadcaster
  ) {
    return;
  }

  /*
   * Só remover se realmente
   * estiver vazia.
   */

  if (
    room.viewers.size >
    0
  ) {
    return;
  }

  /* ================================
     AVISAR CLIENTES
  ================================= */

  io.to(
    roomId
  ).emit(
    "room-closed",
    {
      roomId
    }
  );

  /* ================================
     REMOVER TOKENS
  ================================= */

  removeRoomTokens(
    roomId
  );

  /* ================================
     REMOVER BROADCASTER MAP
  ================================= */

  broadcasters.delete(
    roomId
  );

  /* ================================
     REMOVER SALA
  ================================= */

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
    const now =
      Date.now();

    for (
      const [
        roomId,
        room
      ]
      of rooms
    ) {
      /*
       * Se alguém estiver na sala,
       * não fazemos nada.
       */

      if (
        !isRoomEmpty(room)
      ) {
        /*
         * Segurança extra:
         * sala ativa não possui
         * contador de fechamento.
         */

        room.emptySince =
          null;

        continue;
      }

      /*
       * Se por algum motivo
       * emptySince não existir,
       * iniciamos agora.
       */

      if (
        room.emptySince ===
        null
      ) {
        room.emptySince =
          now;

        console.log(
          `HUNT: sala ${roomId} está vazia. Contagem de 10 minutos iniciada.`
        );

        continue;
      }

      /*
       * Verificar se já passaram
       * 10 minutos.
       */

      const emptyTime =
        now -
        room.emptySince;

      if (
        emptyTime >=
        EMPTY_ROOM_TIMEOUT
      ) {
        console.log(
          `HUNT: sala ${roomId} ficou vazia por 10 minutos. Removendo.`
        );

        removeRoom(
          roomId
        );
      }
    }
  },
  ROOM_CLEANUP_INTERVAL
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

    console.log(
      "HUNT: salas vazias expiram após 10 minutos."
    );

    console.log(
      "HUNT: contador de espectadores oculto da API."
    );
  }
);
