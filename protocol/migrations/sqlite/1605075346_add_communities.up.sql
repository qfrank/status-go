ALTER TABLE chats ADD COLUMN community_id TEXT DEFAULT "";
UPDATE chats SET community_id = "";

ALTER TABLE user_messages ADD COLUMN community_id TEXT DEFAULT "";
UPDATE user_messages SET community_id = "";

CREATE TABLE IF NOT EXISTS communities_communities (
  id BLOB NOT NULL PRIMARY KEY ON CONFLICT REPLACE,
  private_key BLOB,
  description BLOB NOT NULL,
  joined BOOL NOT NULL DEFAULT FALSE,
  verified BOOL NOT NULL DEFAULT FALSE
  );

INSERT INTO communities_communities VALUES(X'039b2da47552aa117a96ea8f1d4d108ba66637c7517a3c94a57b99dbb8a002eda2',NULL,X'0a410f4c132c334319493137d3a091ff45a89a26bbdacc057879893cfebfaf2188d11b950868ce8170d6cbb0dcde85782dabe9328377e0462bfc425fef06960160ce0012c20308031289010a840130783034306332623963663933336635396535303466666230626365383237656534336265366530653231613034313966316331613032396164303334653565626134306464373232626433633661326336303865663263623038613063613534303039656131623832303130366661663463643030393637626439346530303162303712001a0218022a7322065374617475732a69537461747573206973206120736563757265206d6573736167696e67206170702c2063727970746f2077616c6c65742c20616e6420576562332062726f77736572206275696c742077697468207374617465206f66207468652061727420746563686e6f6c6f67792e325f0a2435633332386635342d346434302d343938342d616539362d6239343632343764386462611237120218011a3122087374616e647570732a257374616e6475707320666f722053746174757320636f726520636f6e7472696275746f727332580a2463323766306263342d313430642d343934632d626564342d3861396435643330376431351230120218011a2a220d616e6e6f756e63656d656e74732a19416e6e6f756e63656d656e74732066726f6d205374617475731818',0,1);
