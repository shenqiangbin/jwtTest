import com.sqber.jwtTest.Application;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Date;

@RunWith(SpringRunner.class)
@SpringBootTest(classes={Application.class})
public class TestABC {

    @Test
    public void test1(){

        System.out.println(new Date());

        int expiration = 604800; //秒 604800秒=7天
        Date result = new Date(new Date().getTime() + expiration * 1000);
        System.out.println(result);
        System.out.println("abc");
    }
}
