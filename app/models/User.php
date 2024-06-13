<?php

class User {

  public $username;
  public $password;
  public $auth = false;

  public function __construct() {
        
  }

  public function test () {
    $db = db_connect();
    $statement = $db->prepare("select * from users;");
    $statement->execute();
    $rows = $statement->fetch(PDO::FETCH_ASSOC);
    return $rows;
  }

  public function authenticate($username, $password) {
    /*
    * if username and password good then
    * $this->auth = true;
    */
    $username = strtolower($username);
  	$db = db_connect();

    if (isset($_SESSION['failedAuth']) && $_SESSION['failedAuth'] >= 3) {
      $lockoutTime = 60; // 60 seconds lockout
      $lastFailedTime = $_SESSION['lastFailedAuthTime'];
      $currentTime = time();

      if (($currentTime - $lastFailedTime) < $lockoutTime) {
        $_SESSION['lockout_message'] = "You are locked out for " . ($lockoutTime - ($currentTime - $lastFailedTime)) . " seconds.";
        header('Location: /login');
        die;
      } else {
        $_SESSION['failedAuth'] = 0;
        unset($_SESSION['lockout_message']);
      }
    }
    
    $statement = $db->prepare("select * from users WHERE username = :name;");
    $statement->bindValue(':name', $username);
    $statement->execute();
    $rows = $statement->fetch(PDO::FETCH_ASSOC);
  		
  	if (password_verify($password, $rows['password'])) {
  		$_SESSION['auth'] = 1;
  		$_SESSION['username'] = ucwords($username);
  		unset($_SESSION['failedAuth']);
      $this->logAttempts($username, 'good');
  		header('Location: /home');
  		die;
  	} else {
  	  if(isset($_SESSION['failedAuth'])) {
  	    $_SESSION['failedAuth'] ++;
  		} else {
  			$_SESSION['failedAuth'] = 1;
  		}
      $_SESSION['lastFailedAuthTime'] = time();
      $this->logAttempts($username, 'bad');
      header('Location: /login');
      die;
  	}
  }

  public function creat_user($username, $password){
      $db = db_connect();
      $hashed_password = password_hash($password, PASSWORD_DEFAULT);
      $statement = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
      $statement->bindParam(':username', $username);
      $statement->bindParam(':password', $hashed_password);
      $statement->execute();
      $db->lastInsertId();
      header('Location: /login');
      die;
  }

  private function logAttempts($username, $status){
    $db = db_connect();
    $statement = $db->prepare("INSERT INTO login_attempts(username,attempt_status,attempt_time) VALUES (:username, :status, NOW())");
    $statement->bindParam(':username', $username);
    $statement->bindParam(':status', $status);
    $statement->execute();
      
  }

  
}
