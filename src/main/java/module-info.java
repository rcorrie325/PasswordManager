module dev.krupp.passwordmanager {
    requires javafx.fxml;
    requires atlantafx.base;
    requires javafx.graphics;


    opens edu.cwru.passwordmanager to javafx.fxml;
    exports edu.cwru.passwordmanager;
}