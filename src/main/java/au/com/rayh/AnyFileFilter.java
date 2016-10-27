package au.com.rayh;


import java.io.File;
import java.io.FileFilter;
import java.io.Serializable;

public class AnyFileFilter  implements FileFilter,Serializable {
    public boolean accept(File pathname) {
        return pathname.isFile();
    }
}
