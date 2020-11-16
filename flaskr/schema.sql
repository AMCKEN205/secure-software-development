-- will remove all database tables & entries if run
-- SECURE!!
DROP TABLE IF EXISTS User;
DROP TABLE IF EXISTS Institution;
DROP TABLE IF EXISTS Project;
DROP TABLE IF EXISTS Ticket;
-- tables tied to the user
DROP TABLE IF EXISTS ProjectAccessRights;
DROP TABLE IF EXISTS UserActivityLogFile;
-- tables tied to tickets
DROP TABLE IF EXISTS TicketFile;
DROP TABLE IF EXISTS TicketComment;

-- Avoid using AUTOINCREMENT for IDs.
-- Too obvious for malicious users to guess ids.
-- of users.

CREATE TABLE Institution (
    InstitutionID INTEGER PRIMARY KEY,
    InstitutionName TEXT UNIQUE NOT NULL,
    Address TEXT UNIQUE NOT NULL,
    ContactNumber INTEGER UNIQUE NOT NULL,
    PayPalEmail TEXT UNIQUE NOT NULL
);

CREATE TABLE User (
    UserID INTEGER PRIMARY KEY,
    InstitutionID INTEGER NOT NULL,
    InstitiutionalEmail TEXT UNIQUE NOT NULL,
    UserName TEXT UNIQUE NOT NULL,
    Password TEXT NOT NULL,
    FullName TEXT NOT NULL,
    FOREIGN KEY (InstitutionID) REFERENCES Institution (InstitutionID)
);

CREATE TABLE Project (
    ProjectID INTEGER PRIMARY KEY,
    InstitutionID INTEGER UNIQUE NOT NULL,
    ProjectName TEXT NOT NULL,
    ProjectDescription TEXT,
    ProjectCreationTimestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (InstitutionID) REFERENCES Institution (InstitutionID)
);

CREATE TABLE Ticket(
    TicketID INTEGER PRIMARY KEY,
    UserCreatorID INTEGER NOT NULL,
    UserAssignedToID INTEGER NOT NULL,
    TicketType TEXT NOT NULL,
    TicketNumber INTEGER NOT NULL,
    TicketDate TIMESTAMP NOT NULL,
    TicketTimestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    BugDescription TEXT NOT NULL,
    TicketStatus TEXT NOT NULL,
    Priority TEXT NOT NULL,
    FOREIGN KEY (UserCreatorID) REFERENCES User (UserID),
    FOREIGN KEY (UserAssignedToID) REFERENCES User (UserID)
);

-- Ticket Attributes
CREATE TABLE TicketFile (
    TicketFileId INTEGER PRIMARY KEY, 
    FileName TEXT NOT NULL,
    TicketID INTEGER NOT NULL,
    FileDescription TEXT, 
    FilePath TEXT UNIQUE NOT NULL,
    FileType TEXT NOT NULL,
    FOREIGN KEY (TicketID) REFERENCES Ticket (TicketID)
);

CREATE TABLE TicketComment(
    CommentID INTEGER PRIMARY KEY,
    UserCommentorID INTEGER NOT NULL,
    TicketID INTEGER NOT NULL,
    CommentTitle TEXT NOT NULL,
    CommentText Text NOT NULL,
    CommentTimestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserCommentorID) REFERENCES User (UserID),
    FOREIGN KEY (TicketID) REFERENCES Ticket (TicketID)
);

-- User Attributes
CREATE TABLE UserActivityLogFile(
    UserLogFileID INTEGER PRIMARY KEY,
    UserID INTEGER NOT NULL,
    FileName TEXT UNIQUE NOT NULL,
    FilePath TEXT UNIQUE NOT NULL,
    ActivityFileCreationTimeStamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES User (UserID)
);

CREATE TABLE ProjectAccessRights(
    ProjectAccessRightsID INTEGER PRIMARY KEY,
    ProjectID INTEGER UNIQUE NOT NULL,
    UserID INTEGER UNIQUE NOT NULL,
    ReadAccess BOOLEAN NOT NULL,
    WriteAccess BOOLEAN NOT NULL,
    DeleteAccess BOOLEAN NOT NULL,
    FOREIGN KEY (ProjectID) REFERENCES Project (ProjectID),
    FOREIGN KEY (UserID) REFERENCES User (UserID)
);