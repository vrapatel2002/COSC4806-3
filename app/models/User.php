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
          $statement = $db->prepare("select * from users WHERE username = :name;");
          $statement->bindValue(':name', $username);
          $statement->execute();
          $rows = $statement->fetch(PDO::FETCH_ASSOC);
  		
  		if (password_verify($password, $rows['password'])) {
  			$_SESSION['auth'] = 1;
  			$_SESSION['username'] = ucwords($username);
  			unset($_SESSION['failedAuth']);
  			header('Location: /home');
  			die;
  		} else {
  			if(isset($_SESSION['failedAuth'])) {
  				$_SESSION['failedAuth'] ++; //increment
  			} else {
  				$_SESSION['failedAuth'] = 1;
  			}
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

  public function logAttempts($username, $status){
    $db = db_connect();
    $statement = $db->prepare("INSERT INTO login_attempts(username,attempt_status,attempt_time) VALUES (:username, :status, NOW())");
    $statement->bindParam(':username', $username);
    $statement->bindParam(':status', $status);
    $statement->execute();
      
  }
}
