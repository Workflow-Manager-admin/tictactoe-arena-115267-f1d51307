from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import (
    sessionmaker,
    Session,
    declarative_base,
    relationship,
)
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    JSON,
    desc,
)
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
import os


# Load DB config from env, with validation and fallback for port handling.


def get_env_or_fail(varname: str):
    val = os.getenv(varname)
    if val is None or val == "":
        raise RuntimeError(f"Environment variable {varname} is required for DB connection.")
    return val


POSTGRES_URL = get_env_or_fail('POSTGRES_URL')
POSTGRES_USER = get_env_or_fail('POSTGRES_USER')
POSTGRES_PASSWORD = get_env_or_fail('POSTGRES_PASSWORD')
POSTGRES_DB = get_env_or_fail('POSTGRES_DB')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')  # Default to 5432 if not set

try:
    port_int = int(str(POSTGRES_PORT).strip())
except Exception as e:
    raise RuntimeError(f"POSTGRES_PORT provided ('{POSTGRES_PORT}') is not a valid integer: {e}")

DATABASE_URL = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_URL}:{port_int}/{POSTGRES_DB}"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("SECRET_KEY", "super_secret_key_for_dev_only")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

app = FastAPI(
    title="Tic Tac Toe Backend",
    description=(
        "REST API backend for a multiplayer Tic Tac Toe game, with user "
        "management, gameplay, and leaderboard."
    ),
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "Authentication and User Management"},
        {"name": "game", "description": "Game creation, play, and status"},
        {"name": "leaderboard", "description": "Leaderboard and statistics"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- MODELS ---


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    games_as_x = relationship(
        'Game',
        back_populates='player_x',
        foreign_keys='Game.player_x_id',
        lazy='selectin',
    )
    games_as_o = relationship(
        'Game',
        back_populates='player_o',
        foreign_keys='Game.player_o_id',
        lazy='selectin',
    )
    moves = relationship('Move', back_populates='user', lazy='selectin')


class Game(Base):
    __tablename__ = "games"

    id = Column(Integer, primary_key=True, index=True)
    player_x_id = Column(Integer, ForeignKey('users.id'))
    player_o_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    board = Column(JSON, default=list)  # 3x3 board state
    current_turn = Column(String(1), default='X')  # 'X' or 'O'
    winner = Column(String(1), nullable=True)
    status = Column(String(16), default='active')  # active, completed, draw

    player_x = relationship(
        'User',
        back_populates='games_as_x',
        foreign_keys=[player_x_id],
        lazy='joined',
    )
    player_o = relationship(
        'User',
        back_populates='games_as_o',
        foreign_keys=[player_o_id],
        lazy='joined',
    )
    moves = relationship('Move', back_populates='game', lazy='selectin')


class Move(Base):
    __tablename__ = "moves"

    id = Column(Integer, primary_key=True, index=True)
    game_id = Column(Integer, ForeignKey('games.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    move_number = Column(Integer)
    row = Column(Integer)
    col = Column(Integer)
    symbol = Column(String(1))
    created_at = Column(DateTime, default=datetime.utcnow)

    game = relationship('Game', back_populates='moves', lazy='joined')
    user = relationship('User', back_populates='moves', lazy='joined')


# --- CREATE TABLES ON FIRST RUN ---


Base.metadata.create_all(bind=engine)


# --- PYDANTIC SCHEMAS ---


class UserBase(BaseModel):
    username: str = Field(..., description="Username of the user")


class UserCreate(UserBase):
    password: str = Field(..., min_length=6)


class UserOut(UserBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class GameCreate(BaseModel):
    opponent_username: str


class MoveCreate(BaseModel):
    row: int = Field(ge=0, le=2, description="Row coordinate 0-2")
    col: int = Field(ge=0, le=2, description="Col coordinate 0-2")


class GameOut(BaseModel):
    id: int
    player_x_username: str
    player_o_username: Optional[str]
    board: list
    current_turn: str
    winner: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class GameHistory(BaseModel):
    game_id: int
    opponent: str
    result: str  # 'win', 'loss', 'draw'
    played_at: datetime


class MoveOut(BaseModel):
    row: int
    col: int
    symbol: str
    username: str
    created_at: datetime


class LeaderboardEntry(BaseModel):
    username: str
    games_played: int
    wins: int
    draws: int
    losses: int


# --- UTILS ---


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials.",
            )
        return username
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials"
        )


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    username = decode_access_token(token)
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def board_after_move(board, row, col, symbol):
    # Deep copy of board to not mutate
    import copy
    b = copy.deepcopy(board)
    b[row][col] = symbol
    return b


def check_winner(board):
    # board is a 3x3 list of lists
    for i in range(3):
        if board[i][0] != '' and board[i][0] == board[i][1] == board[i][2]:
            return board[i][0]
        if board[0][i] != '' and board[0][i] == board[1][i] == board[2][i]:
            return board[0][i]
    if board[0][0] != '' and board[0][0] == board[1][1] == board[2][2]:
        return board[0][0]
    if board[0][2] != '' and board[0][2] == board[1][1] == board[2][0]:
        return board[0][2]
    return None


def is_draw(board):
    return all((board[r][c] != '' for r in range(3) for c in range(3)))


# --- ROUTES ---


@app.get("/", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}


# --- Authentication ---


# PUBLIC_INTERFACE
@app.post(
    "/register",
    response_model=UserOut,
    tags=["auth"],
    summary="Register new user",
)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Registers a new user. Usernames must be unique."""
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=409, detail="Username already registered")
    hashed_pw = get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_pw)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# PUBLIC_INTERFACE
@app.post(
    "/token",
    response_model=Token,
    tags=["auth"],
    summary="Login user",
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Authenticate user and get JWT token."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# --- Game Endpoints ---


# PUBLIC_INTERFACE
@app.post(
    "/games",
    response_model=GameOut,
    tags=["game"],
    summary="Start new game",
)
def start_game(
    request: GameCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Start a new game with another user."""
    opponent = db.query(User).filter(User.username == request.opponent_username).first()
    if not opponent:
        raise HTTPException(status_code=404, detail="Opponent not found")
    if opponent.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot play against yourself")
    # Randomly assign X or O
    import random
    as_x = random.choice([True, False])
    player_x_id = current_user.id if as_x else opponent.id
    player_o_id = current_user.id if not as_x else opponent.id
    initial_board = [['', '', ''], ['', '', ''], ['', '', '']]
    game = Game(
        player_x_id=player_x_id,
        player_o_id=player_o_id,
        board=initial_board,
        current_turn='X',
        status='active',
    )
    db.add(game)
    db.commit()
    db.refresh(game)
    return GameOut(
        id=game.id,
        player_x_username=game.player_x.username,
        player_o_username=game.player_o.username,
        board=game.board,
        current_turn=game.current_turn,
        winner=game.winner,
        status=game.status,
        created_at=game.created_at,
        updated_at=game.updated_at,
    )


# PUBLIC_INTERFACE
@app.get(
    "/games/{game_id}",
    response_model=GameOut,
    tags=["game"],
    summary="Get game state",
)
def get_game(
    game_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the current state and board of a game you are part of."""
    game = db.query(Game).filter(Game.id == game_id).first()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if not (game.player_x_id == current_user.id or game.player_o_id == current_user.id):
        raise HTTPException(status_code=403, detail="You are not a player in this game")
    return GameOut(
        id=game.id,
        player_x_username=game.player_x.username,
        player_o_username=game.player_o.username,
        board=game.board,
        current_turn=game.current_turn,
        winner=game.winner,
        status=game.status,
        created_at=game.created_at,
        updated_at=game.updated_at,
    )


# PUBLIC_INTERFACE
@app.post(
    "/games/{game_id}/move",
    response_model=GameOut,
    tags=["game"],
    summary="Make a move in a game",
)
def make_move(
    game_id: int,
    move: MoveCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Make a move for the current user in the given game. Checks turn and validity."""
    game = db.query(Game).filter(Game.id == game_id).first()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if not (game.player_x_id == current_user.id or game.player_o_id == current_user.id):
        raise HTTPException(status_code=403, detail="You are not a player in this game")
    if game.status != 'active':
        raise HTTPException(status_code=400, detail="Game already completed")
    # Determine current player symbol
    symbol = 'X' if game.player_x_id == current_user.id else 'O'
    if game.current_turn != symbol:
        raise HTTPException(status_code=400, detail="Not your turn")
    board = game.board if game.board else [['', '', ''], ['', '', ''], ['', '', '']]
    if board[move.row][move.col] != '':
        raise HTTPException(status_code=400, detail="Cell already occupied")
    # Make move
    board = board_after_move(board, move.row, move.col, symbol)
    winner = check_winner(board)
    draw = is_draw(board)
    game.board = board
    game.current_turn = 'O' if symbol == 'X' else 'X'
    if winner:
        game.winner = winner
        game.status = 'completed'
    elif draw:
        game.status = 'draw'
    db_move = Move(
        game_id=game.id,
        user_id=current_user.id,
        move_number=len(game.moves) + 1,
        row=move.row,
        col=move.col,
        symbol=symbol,
    )
    db.add(db_move)
    db.commit()
    db.refresh(game)
    return GameOut(
        id=game.id,
        player_x_username=game.player_x.username,
        player_o_username=game.player_o.username,
        board=game.board,
        current_turn=game.current_turn,
        winner=game.winner,
        status=game.status,
        created_at=game.created_at,
        updated_at=game.updated_at,
    )


# PUBLIC_INTERFACE
@app.get(
    "/games/history",
    response_model=List[GameHistory],
    tags=["game"],
    summary="Get current user's game history",
)
def get_game_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List recent games of the logged-in user, with their result."""
    games = db.query(Game).filter(
        (Game.player_x_id == current_user.id) | (Game.player_o_id == current_user.id)
    ).order_by(desc(Game.created_at)).limit(25).all()
    history = []
    for game in games:
        if game.status not in {'completed', 'draw'}:
            continue
        # Win/loss/draw
        if game.status == 'draw':
            result = 'draw'
        elif game.winner == 'X':
            result = 'win' if game.player_x_id == current_user.id else 'loss'
        elif game.winner == 'O':
            result = 'win' if game.player_o_id == current_user.id else 'loss'
        else:
            result = 'unknown'
        opponent = (
            game.player_o.username if game.player_x_id == current_user.id
            else game.player_x.username
        )
        history.append(GameHistory(
            game_id=game.id,
            opponent=opponent,
            result=result,
            played_at=game.updated_at,
        ))
    return history


# PUBLIC_INTERFACE
@app.get(
    "/games/{game_id}/moves",
    response_model=List[MoveOut],
    tags=["game"],
    summary="Get moves for a game",
)
def list_moves(
    game_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all moves (history) for a given game."""
    game = db.query(Game).filter(Game.id == game_id).first()
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if not (game.player_x_id == current_user.id or game.player_o_id == current_user.id):
        raise HTTPException(
            status_code=403, detail="You are not a player in this game"
        )
    moves = db.query(Move).filter(
        Move.game_id == game_id
    ).order_by(Move.move_number).all()
    return [
        MoveOut(
            row=m.row,
            col=m.col,
            symbol=m.symbol,
            username=m.user.username,
            created_at=m.created_at,
        ) for m in moves
    ]


# --- Leaderboard ---


# PUBLIC_INTERFACE
@app.get(
    "/leaderboard",
    response_model=List[LeaderboardEntry],
    tags=["leaderboard"],
    summary="Leaderboard ranking",
)
def leaderboard(db: Session = Depends(get_db)):
    """Show the leaderboard: users with most wins, with stats."""
    users = db.query(User).all()
    entries = []
    for user in users:
        games_played = db.query(Game).filter(
            (Game.player_x_id == user.id) | (Game.player_o_id == user.id)
        ).count()
        # Wins is winner and player id matches
        wins = db.query(Game).filter(
            ((Game.player_x_id == user.id) & (Game.winner == 'X'))
            | ((Game.player_o_id == user.id) & (Game.winner == 'O'))
        ).count()
        draws = db.query(Game).filter(
            ((Game.player_x_id == user.id) | (Game.player_o_id == user.id))
            & (Game.status == 'draw')
        ).count()
        losses = games_played - wins - draws
        entries.append(LeaderboardEntry(
            username=user.username,
            games_played=games_played,
            wins=wins,
            draws=draws,
            losses=losses,
        ))
    entries.sort(key=lambda e: (-e.wins, -e.games_played))
    return entries


# --- Swagger help for WebSocket support (if added) ---


@app.get("/websocket-usage", tags=["game"], summary="WebSocket usage documentation")
def websocket_usage():
    """
    Project does not use WebSocket for gameplay.
    All interactions are via HTTP REST.
    """
    return {
        "note": (
            "All gameplay and game state retrieval is via HTTP REST endpoints. "
            "No WebSocket used in current backend."
        )
    }
