CREATE TABLE IF NOT EXISTS `Members` (
    `member_id`   VARCHAR(50)  NOT NULL,
    `name`        VARCHAR(50)  NOT NULL,
    `pwd`         VARCHAR(100) NOT NULL,

    PRIMARY KEY(`member_id`)
);

CREATE TABLE IF NOT EXISTS `Authorities` (
    `member_id`   VARCHAR(50)  NOT NULL,
    `authority`   VARCHAR(50)  NOT NULL,

    PRIMARY KEY(`member_id`)
);

-- TODO #3: change password column value
MERGE INTO `Members` KEY (`member_id`) VALUES ( 'admin' , 'Administrator', RAWTOHEX(HASH('SHA256', STRINGTOUTF8('admin'), 1024)));
MERGE INTO `Members` KEY (`member_id`) VALUES ( 'member', 'I reMember', RAWTOHEX(HASH('SHA256', STRINGTOUTF8('member'), 1024)));
MERGE INTO `Members` KEY (`member_id`) VALUES ( 'guest' , 'gu-est', RAWTOHEX(HASH('SHA256', STRINGTOUTF8('guest'), 1024)));

MERGE INTO `Authorities` KEY (`member_id`) VALUES ( 'admin' , 'ROLE_ADMIN'  );
MERGE INTO `Authorities` KEY (`member_id`) VALUES ( 'member', 'ROLE_MEMBER' );
MERGE INTO `Authorities` KEY (`member_id`) VALUES ( 'guest', 'ROLE_GUEST' );
