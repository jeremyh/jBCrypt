import java.io.*;

import junit.framework.TestCase;
import org.mindrot.*;


public class TestMain extends TestCase {
  ByteArrayOutputStream stdout = new ByteArrayOutputStream();
  String fixedSalt = "$2a$10$MkkJUCZctqHDtrcWu0gfOe";
  StubbedMainUtil stubbedMainUtil = new StubbedMainUtil(fixedSalt);

  @Override
  public void setUp() throws Exception {
    Main.MAIN_UTIL = stubbedMainUtil;
    PrintStream printStream = new PrintStream(stdout);
    System.setOut(printStream);
  }

  public void testIfArgEmptyShowInstruction() throws Exception {
    Main.main(new String[0]);
    assertEquals("Please specify a secret\n", stdout.toString());
  }

  public void testIfArgEmptyExitsWithStatusCode1() throws Exception {
    Main.main(new String[0]);
    assertEquals(1, stubbedMainUtil.lastExitCode);
  }

  public void testIfArgsProvidedReturnHashedSecret() throws Exception {
    String secret = "pa$$w0rd";
    String expectedHash = BCrypt.hashpw(secret, fixedSalt) + "\n";

    Main.main(new String[]{secret});
    String calculatedHash = stdout.toString();

    assertEquals(expectedHash, calculatedHash);
  }

  public void testIfArgsProvidedExitsWithStatusCode0() throws Exception {
    Main.main(new String[]{"dummy"});
    assertEquals(0, stubbedMainUtil.lastExitCode);
  }

  private class StubbedMainUtil extends MainUtil {
    final String fixedSalt;
    int lastExitCode = Integer.MAX_VALUE;

    public StubbedMainUtil(String fixedSalt) {
      super();
      this.fixedSalt = fixedSalt;
    }

    @Override
    public void exit(int exitCode) {
      lastExitCode = exitCode;
    }

    @Override
    public String genSalt() {
      return fixedSalt;
    }
  }
}
