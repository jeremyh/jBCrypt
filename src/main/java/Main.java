import org.mindrot.*;

public class Main {

  static MainUtil MAIN_UTIL = new MainUtil();

  public static void main(String[] args) {
    String password;
    String salt;

    if (args.length==0) {
      System.out.println("Please specify a secret");
      MAIN_UTIL.exit(1);
    } else {
      password = args[0];
      salt = MAIN_UTIL.genSalt();
      System.out.println(BCrypt.hashpw(password, salt));
      MAIN_UTIL.exit(0);
    }
  }

}


class MainUtil {
  public void exit(int exitCode) {
    System.exit(exitCode);
  }

  public String genSalt() {
    return BCrypt.gensalt();
  }
}
