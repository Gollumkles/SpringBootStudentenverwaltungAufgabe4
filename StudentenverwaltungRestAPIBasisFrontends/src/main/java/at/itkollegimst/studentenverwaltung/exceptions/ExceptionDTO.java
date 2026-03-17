package at.itkollegimst.studentenverwaltung.exceptions;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ExceptionDTO {

    private String code;
    private String message;
}
